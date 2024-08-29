use ruma::{OwnedUserId, UserId};

use crate::{service, utils, Error, KeyValueDatabase, Result};

impl service::sso::Data for KeyValueDatabase {
    fn save_subject(&self, provider: &str, user_id: &UserId, subject: &str) -> Result<()> {
        let mut key = provider.as_bytes().to_vec();
        key.push(0xff);
        key.extend_from_slice(subject.as_bytes());

        self.providersubjectid_userid.insert(&key, user_id.as_bytes())
    }

    fn user_from_subject(&self, provider: &str, subject: &str) -> Result<Option<OwnedUserId>> {
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
