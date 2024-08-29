use std::{
    borrow::Borrow,
    collections::HashSet,
    hash::{Hash, Hasher},
    sync::Arc,
};

use crate::{
    api::client_server::{LOGIN_TOKEN_EXPIRATION_SECS, TOKEN_LENGTH},
    config::IdpConfig,
    utils, Error, Result,
};
use futures_util::future::{self};
use http::HeaderValue;
use mas_oidc_client::{
    http_service::HttpService,
    requests::{authorization_code::AuthorizationValidationData, discovery},
    types::oidc::VerifiedProviderMetadata,
};
use ruma::{api::client::session::get_login_types::v3::IdentityProvider, OwnedUserId, UserId};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tower::BoxError;
use tower_http::{set_header::SetRequestHeaderLayer, ServiceBuilderExt};
use tracing::error;
use url::Url;

use crate::services;

mod data;
pub use data::Data;

pub const SSO_AUTH_EXPIRATION_SECS: u64 = 60 * 60;
pub const SSO_TOKEN_EXPIRATION_SECS: u64 = 60 * 2;
pub const SSO_SESSION_COOKIE: &str = "sso-auth";
pub const SUBJECT_CLAIM_KEY: &str = "sub";

pub struct Service {
    db: &'static dyn Data,
    service: HttpService,
    providers: OnceCell<HashSet<Provider>>,
}

impl Service {
    pub fn build(db: &'static dyn Data) -> Result<Arc<Self>> {
        let client = tower::ServiceBuilder::new()
            .map_err(BoxError::from)
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(10),
            ))
            .layer(mas_http::BytesToBodyRequestLayer)
            .layer(mas_http::BodyToBytesResponseLayer)
            .layer(SetRequestHeaderLayer::overriding(
                http::header::USER_AGENT,
                HeaderValue::from_static("conduit/0.9-alpha"),
            ))
            .concurrency_limit(10)
            .follow_redirects()
            .service(mas_http::make_untraced_client());

        Ok(Arc::new(Self {
            db,
            service: HttpService::new(client),
            providers: OnceCell::new(),
        }))
    }

    pub fn service(&self) -> &HttpService {
        &self.service
    }

    pub async fn start_handler(&self) -> Result<()> {
        let providers = services().globals.config.idps.iter();

        self.providers
            .get_or_try_init(|| async move {
                future::try_join_all(providers.map(Provider::fetch_metadata))
                    .await
                    .map(Vec::into_iter)
                    .map(HashSet::from_iter)
            })
            .await?;

        Ok(())
    }

    pub fn get(&self, provider: &str) -> Option<&Provider> {
        let providers = self.providers.get().expect("");

        providers.get(provider)
    }

    pub fn login_type(&self) -> impl Iterator<Item = IdentityProvider> + '_ {
        let providers = self.providers.get().expect("");

        providers.iter().map(|p| p.config.inner.clone())
    }

    pub fn user_from_subject(&self, provider: &str, subject: &str) -> Result<Option<OwnedUserId>> {
        self.db.user_from_subject(provider, subject)
    }
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub config: &'static IdpConfig,
    pub metadata: VerifiedProviderMetadata,
}

impl Provider {
    pub async fn fetch_metadata(config: &'static IdpConfig) -> Result<Self> {
        discovery::discover(services().sso.service(), &config.issuer)
            .await
            .map(|metadata| Provider { config, metadata })
            .map_err(|e| {
                error!(
                    "Failed to fetch identity provider metadata ({}): {}",
                    &config.inner.id, e
                );

                Error::bad_config("Failed to fetch identity provider metadata.")
            })
    }
}

impl Borrow<str> for Provider {
    fn borrow(&self) -> &str {
        self.config.borrow()
    }
}

impl PartialEq for Provider {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl Eq for Provider {}

impl Hash for Provider {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.config.hash(hasher)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct LoginToken {
    pub iss: String,
    pub aud: OwnedUserId,
    pub sub: String,
    pub exp: u64,
}

impl LoginToken {
    pub fn new(provider: String, user_id: OwnedUserId) -> Self {
        Self {
            iss: provider,
            aud: user_id,
            sub: utils::random_string(TOKEN_LENGTH),
            exp: utils::millis_since_unix_epoch()
                .checked_add(LOGIN_TOKEN_EXPIRATION_SECS * 1000)
                .expect("time overflow"),
        }
    }
    pub fn audience(self) -> OwnedUserId {
        self.aud
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationData {
    pub provider: String,
    pub redirect_url: String,
    #[serde(flatten, with = "AuthorizationValidationDataDef")]
    pub inner: AuthorizationValidationData,
}

impl ValidationData {
    pub fn new(provider: String, redirect_url: String, inner: AuthorizationValidationData) -> Self {
        Self {
            provider,
            redirect_url,
            inner,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(remote = "AuthorizationValidationData")]
pub struct AuthorizationValidationDataDef {
    pub state: String,
    pub nonce: String,
    pub redirect_uri: Url,
    pub code_challenge_verifier: Option<String>,
}

impl From<AuthorizationValidationData> for AuthorizationValidationDataDef {
    fn from(
        AuthorizationValidationData {
            state,
            nonce,
            redirect_uri,
            code_challenge_verifier,
        }: AuthorizationValidationData,
    ) -> Self {
        Self {
            state,
            nonce,
            redirect_uri,
            code_challenge_verifier,
        }
    }
}