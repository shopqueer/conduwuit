use ruma::{OwnedUserId, UserId};

use crate::Result;

pub trait Data: Send + Sync {
    fn save_subject(&self, provider: &str, user_id: &UserId, subject: &str) -> Result<()>;

    fn user_from_subject(&self, provider: &str, subject: &str) -> Result<Option<OwnedUserId>>;
}