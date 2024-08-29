use std::{borrow::Borrow, collections::HashMap, iter::Iterator, time::SystemTime};

use crate::{
    config::IdpConfig,
    service::sso::{
        LoginToken, ValidationData, SSO_AUTH_EXPIRATION_SECS, SSO_SESSION_COOKIE, SUBJECT_CLAIM_KEY,
    },
    services, utils, Error, Result, Ruma,
};
use futures_util::TryFutureExt;
use mas_oidc_client::{
    requests::{
        authorization_code::{self, AuthorizationRequestData},
        jose::{self, JwtVerificationData},
        userinfo,
    },
    types::{
        client_credentials::ClientCredentials,
        iana::jose::JsonWebSignatureAlg,
        requests::{AccessTokenResponse, AuthorizationResponse},
    },
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use ruma::{
    api::client::{
        error::ErrorKind,
        media::create_content,
        session::{sso_login, sso_login_with_provider},
    },
    events::{room::message::RoomMessageEventContent, GlobalAccountDataEventType},
    push, UserId,
};
use serde_json::Value;
use tracing::{error, info, warn};
use url::Url;

pub const CALLBACK_PATH: &str = "/_matrix/client/unstable/conduit/callback";

/// # `GET /_matrix/client/v3/login/sso/redirect`
///
/// Redirect the user to the SSO interfa.
/// TODO: this should be removed once Ruma supports trailing slashes.
pub async fn get_sso_redirect_route(
    Ruma {
        body,
        sender_user,
        sender_device,
        sender_servername,
        json_body,
        ..
    }: Ruma<sso_login::v3::Request>,
) -> Result<sso_login::v3::Response> {
    let sso_login_with_provider::v3::Response { location, cookie } =
        get_sso_redirect_with_provider_route(
            Ruma {
                body: sso_login_with_provider::v3::Request::new(
                    Default::default(),
                    body.redirect_url,
                ),
                sender_user,
                sender_device,
                sender_servername,
                json_body,
                appservice_info: None,
            }
            .into(),
        )
        .await?;

    Ok(sso_login::v3::Response { location, cookie })
}

/// # `GET /_matrix/client/v3/login/sso/redirect/{idpId}`
///
/// Redirects the user to the SSO interface.
pub async fn get_sso_redirect_with_provider_route(
    body: Ruma<sso_login_with_provider::v3::Request>,
) -> Result<sso_login_with_provider::v3::Response> {
    let idp_ids: Vec<&str> = services()
        .globals
        .config
        .idps
        .iter()
        .map(Borrow::borrow)
        .collect();

    let provider = match &*idp_ids {
        [] => {
            return Err(Error::BadRequest(
                ErrorKind::forbidden(),
                "Single Sign-On is disabled.",
            ));
        }
        [idp_id] => services().sso.get(idp_id).expect("we know it exists"),
        [_, ..] => services().sso.get(&body.idp_id).ok_or_else(|| {
            Error::BadRequest(ErrorKind::InvalidParam, "Unknown identity provider.")
        })?,
    };

    let redirect_url = body
        .redirect_url
        .parse::<Url>()
        .map_err(|_| Error::BadRequest(ErrorKind::InvalidParam, "Invalid redirect_url."))?;

    let mut callback = services()
        .globals
        .well_known_client()
        .parse::<Url>()
        .map_err(|_| Error::bad_config("Invalid well_known_client url."))?;
    callback.set_path(CALLBACK_PATH);

    let (auth_url, validation_data) = authorization_code::build_authorization_url(
        provider.metadata.authorization_endpoint().clone(),
        AuthorizationRequestData::new(
            provider.config.client_id.clone(),
            provider.config.scopes.clone(),
            callback,
        ),
        &mut StdRng::from_entropy(),
    )
    .map_err(|_| Error::BadRequest(ErrorKind::Unknown, "Failed to build authorization_url."))?;

    let signed = services().globals.sign_claims(&ValidationData::new(
        Borrow::<str>::borrow(provider).to_owned(),
        redirect_url.to_string(),
        validation_data,
    ));

    Ok(sso_login_with_provider::v3::Response {
        location: auth_url.to_string(),
        cookie: Some(
            utils::build_cookie(
                SSO_SESSION_COOKIE,
                &signed,
                CALLBACK_PATH,
                Some(SSO_AUTH_EXPIRATION_SECS),
            )
            .to_string(),
        ),
    })
}

/// # `GET /_conduit/client/sso/callback`
///
/// Validate the authorization response received from the identity provider.
/// On success, generate a login token, add it to `redirectUrl` as a query and perform the redirect.
/// If this is the first login, register the user, possibly interactively through a fallback page.
pub async fn handle_callback_route(
    body: Ruma<sso_callback::Request>,
) -> Result<sso_login_with_provider::v3::Response> {
    let sso_callback::Request {
        response:
            AuthorizationResponse {
                code,
                access_token: _,
                token_type: _,
                id_token: _,
                expires_in: _,
            },
        cookie,
    } = body.body;

    let ValidationData {
        provider,
        redirect_url,
        inner: validation_data,
    } = services()
        .globals
        .validate_claims(&cookie, None)
        .map_err(|_| {
            Error::BadRequest(ErrorKind::InvalidParam, "Invalid value for session cookie.")
        })?;

    let provider = services().sso.get(&provider).ok_or_else(|| {
        Error::BadRequest(
            ErrorKind::InvalidParam,
            "Unknown provider for session cookie.",
        )
    })?;

    let IdpConfig {
        client_id,
        client_secret,
        auth_method,
        ..
    } = provider.config.clone();

    let credentials = match &*auth_method {
        "basic" => ClientCredentials::ClientSecretBasic {
            client_id,
            client_secret,
        },
        "post" => ClientCredentials::ClientSecretPost {
            client_id,
            client_secret,
        },
        _ => todo!(),
    };
    let ref jwks = jose::fetch_jwks(services().sso.service(), provider.metadata.jwks_uri())
        .await
        .map_err(|_| Error::bad_config("Failed to fetch signing keys for token endpoint."))?;
    let idt_verification_data = Some(JwtVerificationData {
        jwks,
        issuer: &provider.config.issuer,
        client_id: &provider.config.client_id,
        signing_algorithm: &JsonWebSignatureAlg::Rs256,
    });

    let (
        AccessTokenResponse {
            access_token,
            refresh_token: _,
            token_type: _,
            expires_in: _,
            scope: _,
            ..
        },
        Some(id_token),
    ) = authorization_code::access_token_with_authorization_code(
        services().sso.service(),
        credentials,
        provider.metadata.token_endpoint(),
        code.unwrap_or_default(),
        validation_data,
        idt_verification_data,
        SystemTime::now().into(),
        &mut StdRng::from_entropy(),
    )
    .await
    .map_err(|_| Error::bad_config("Failed to fetch access token."))?
    else {
        unreachable!("ID token should never be empty")
    };

    let mut userinfo = HashMap::default();
    if let Some(endpoint) = provider.metadata.userinfo_endpoint.as_ref() {
        userinfo = userinfo::fetch_userinfo(
            services().sso.service(),
            endpoint,
            &access_token,
            None,
            &id_token,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch claims for userinfo endpoint: {:?}", e);

            Error::bad_config("Failed to fetch claims for userinfo endpoint.")
        })?;
    }

    let (_, id_token) = id_token.into_parts();

    info!("userinfo: {:?}", &userinfo);
    info!("id_token: {:?}", &id_token);

    let subject = match id_token.get(SUBJECT_CLAIM_KEY) {
        Some(Value::String(s)) => s.to_owned(),
        Some(Value::Number(n)) => n.to_string(),
        value => {
            return Err(Error::BadRequest(
                ErrorKind::Unknown,
                value
                    .map(|_| {
                        error!("Subject claim is missing from ID token: {id_token:?}");

                        "Subject claim is missing from ID token."
                    })
                    .unwrap_or("Subject claim should be a string or number."),
            ));
        }
    };

    let user_id = match services()
        .sso
        .user_from_subject(Borrow::<str>::borrow(provider), &subject)?
    {
        Some(user_id) => user_id,
        None => {
            let mut localpart = subject.clone();

            let user_id = loop {
                match UserId::parse_with_server_name(&*localpart, services().globals.server_name())
                    .map(|user_id| {
                        (
                            user_id.clone(),
                            services().users.exists(&user_id).unwrap_or(true),
                        )
                    }) {
                    Ok((user_id, false)) => break user_id,
                    _ => {
                        let n: u8 = rand::thread_rng().gen();

                        localpart = format!("{}{}", localpart, n % 10);
                    }
                }
            };

            services().users.set_placeholder_password(&user_id)?;
            let displayname = id_token
                .get("preferred_username")
                .or(id_token.get("nickname"));
            let mut displayname = displayname
                .as_deref()
                .map(Value::as_str)
                .flatten()
                .unwrap_or(user_id.localpart())
                .to_owned();

            // If enabled append lightning bolt to display name (default true)
            if services().globals.enable_lightning_bolt() {
                displayname.push_str(" ⚡️");
            }

            services()
                .users
                .set_displayname(&user_id, Some(displayname.clone()))?;

            if let Some(Value::String(url)) = userinfo.get("picture").or(id_token.get("picture")) {
                let req = services()
                    .globals
                    .default_client()
                    .get(url)
                    .send()
                    .and_then(reqwest::Response::bytes);

                if let Ok(file) = req.await {
                    let _ = crate::api::client_server::create_content_route(Ruma {
                        body: create_content::v3::Request::new(file.to_vec()),
                        sender_user: None,
                        sender_device: None,
                        sender_servername: None,
                        json_body: None,
                        appservice_info: None,
                    })
                    .await
                    .and_then(|res| {
                        tracing::info!("successfully imported avatar for {}", &user_id);

                        services()
                            .users
                            .set_avatar_url(&user_id, Some(res.content_uri))
                    });
                }
            }

            // Initial account data
            services().account_data.update(
                None,
                &user_id,
                GlobalAccountDataEventType::PushRules.to_string().into(),
                &serde_json::to_value(ruma::events::push_rules::PushRulesEvent {
                    content: ruma::events::push_rules::PushRulesEventContent {
                        global: push::Ruleset::server_default(&user_id),
                    },
                })
                .expect("to json always works"),
            )?;

            info!("New user {} registered on this server.", user_id);
            services()
                .admin
                .send_message(RoomMessageEventContent::notice_plain(format!(
                    "New user {user_id} registered on this server."
                )));

            if let Some(admin_room) = services().admin.get_admin_room()? {
                if services()
                    .rooms
                    .state_cache
                    .room_joined_count(&admin_room)?
                    == Some(1)
                {
                    services()
                        .admin
                        .make_user_admin(&user_id, displayname.to_owned())
                        .await?;

                    warn!("Granting {} admin privileges as the first user", user_id);
                }
            }

            user_id
        }
    };

    let signed = services().globals.sign_claims(&LoginToken::new(
        Borrow::<str>::borrow(provider).to_owned(),
        user_id,
    ));

    let mut redirect_url: Url = redirect_url.parse().expect("");
    redirect_url
        .query_pairs_mut()
        .append_pair("loginToken", &signed);

    Ok(sso_login_with_provider::v3::Response {
        location: redirect_url.to_string(),
        cookie: Some(utils::build_cookie(SSO_SESSION_COOKIE, "", CALLBACK_PATH, None).to_string()),
    })
}

mod sso_callback {
    use axum_extra::headers::{self, HeaderMapExt};
    use http::Method;
    use mas_oidc_client::types::requests::AuthorizationResponse;
    use ruma::{
        api::{
            client::{session::sso_login_with_provider, Error},
            error::{FromHttpRequestError, HeaderDeserializationError},
            IncomingRequest, Metadata,
        },
        metadata,
    };

    use crate::service::sso::SSO_SESSION_COOKIE;

    pub const METADATA: Metadata = metadata! {
        method: GET,
        rate_limited: false,
        authentication: None,
        history: {
            1.0 => "/_matrix/client/unstable/conduit/callback",
        }
    };

    pub struct Request {
        pub response: AuthorizationResponse,
        pub cookie: String,
    }

    impl IncomingRequest for Request {
        type EndpointError = Error;
        type OutgoingResponse = sso_login_with_provider::v3::Response;

        const METADATA: Metadata = METADATA;

        fn try_from_http_request<B, S>(
            req: http::Request<B>,
            _path_args: &[S],
        ) -> Result<Self, FromHttpRequestError>
        where
            B: AsRef<[u8]>,
            S: AsRef<str>,
        {
            if !(req.method() == METADATA.method
                || req.method() == Method::HEAD && METADATA.method == Method::GET)
            {
                return Err(FromHttpRequestError::MethodMismatch {
                    expected: METADATA.method,
                    received: req.method().clone(),
                });
            }

            let response: AuthorizationResponse =
                serde_html_form::from_str(req.uri().query().unwrap_or(""))?;

            let Some(cookie) = req
                .headers()
                .typed_get()
                .and_then(|cookie: headers::Cookie| {
                    cookie.get(SSO_SESSION_COOKIE).map(str::to_owned)
                })
            else {
                return Err(HeaderDeserializationError::MissingHeader(
                    "Cookie".to_owned(),
                ))?;
            };

            Ok(Self { response, cookie })
        }
    }
}