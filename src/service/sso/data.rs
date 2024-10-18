use ruma::{OwnedUserId, UserId};
use std::sync::Arc;
use database::{Database, Map};
use conduit::{utils, Error, Result};

use crate::{globals, Dep};


pub struct Data {
	userid_providersubjectid: Arc<Map>,
	providersubjectid_userid: Arc<Map>,
	pub(super) db: Arc<Database>,
	services: Services,
}

struct Services {
	globals: Dep<globals::Service>,
}

impl Data {
    pub(super) fn new(args: &crate::Args<'_>) -> Self {
        let db = &args.db;
        Self {
            userid_providersubjectid: db["userid_providersubjectid"].clone(),
            providersubjectid_userid: db["providersubjectid_userid"].clone(),
            db: args.db.clone(),
            services: Services {
                globals: args.depend::<globals::Service>("globals"),
            },
        }
    }
    pub fn save_subject(&self, provider: &str, user_id: &UserId, subject: &str) -> Result<()> {
        let mut key = provider.as_bytes().to_vec();
        key.push(0xff);
        key.extend_from_slice(subject.as_bytes());

        self.providersubjectid_userid.insert(&key, user_id.as_bytes())

    }

    pub fn user_from_subject(&self, provider: &str, subject: &str) -> Result<Option<OwnedUserId>> {
        let mut key = provider.as_bytes().to_vec();
        key.push(0xff);
        key.extend_from_slice(subject.as_bytes());

        self.providersubjectid_userid.get(&key)?.map_or(Ok(None), |bytes| {
            Some(
                UserId::parse(utils::string_from_bytes(&bytes).map_err(|_| {
                    Error::bad_database("User ID in claim_userid is invalid unicode.")
                })?)
                .map_err(|_| Error::bad_database("User ID in claim_userid is invalid.")),
            )
            .transpose()
        })
    }

}
