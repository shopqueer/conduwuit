pub(super) mod account;
pub(super) mod alias;
pub(super) mod backup;
pub(super) mod capabilities;
pub(super) mod config;
pub(super) mod context;
pub(super) mod device;
pub(super) mod directory;
pub(super) mod filter;
pub(super) mod keys;
pub(super) mod media;
pub(super) mod membership;
pub(super) mod message;
pub(super) mod openid;
pub(super) mod presence;
pub(super) mod profile;
pub(super) mod push;
pub(super) mod read_marker;
pub(super) mod redact;
pub(super) mod relations;
pub(super) mod report;
pub(super) mod room;
pub(super) mod search;
pub(super) mod session;
pub(super) mod space;
pub(super) mod sso;
pub(super) mod state;
pub(super) mod sync;
pub(super) mod tag;
pub(super) mod thirdparty;
pub(super) mod threads;
pub(super) mod to_device;
pub(super) mod typing;
pub(super) mod unstable;
pub(super) mod unversioned;
pub(super) mod user_directory;
pub(super) mod voip;

pub(super) use account::*;
pub(super) use alias::*;
pub(super) use backup::*;
pub(super) use capabilities::*;
pub(super) use config::*;
pub(super) use context::*;
pub(super) use device::*;
pub(super) use directory::*;
pub(super) use filter::*;
pub(super) use keys::*;
pub(super) use media::*;
pub(super) use membership::*;
pub use membership::{join_room_by_id_helper, leave_all_rooms, leave_room, validate_and_add_event_id};
pub(super) use message::*;
pub(super) use openid::*;
pub(super) use presence::*;
pub(super) use profile::*;
pub use profile::{update_all_rooms, update_avatar_url, update_displayname};
pub(super) use push::*;
pub(super) use read_marker::*;
pub(super) use redact::*;
pub(super) use relations::*;
pub(super) use report::*;
pub(super) use room::*;
pub(super) use search::*;
pub(super) use session::*;
pub(super) use space::*;
pub(super) use sso::*;
pub(super) use state::*;
pub(super) use sync::*;
pub(super) use tag::*;
pub(super) use thirdparty::*;
pub(super) use threads::*;
pub(super) use to_device::*;
pub(super) use typing::*;
pub(super) use unstable::*;
pub(super) use unversioned::*;
pub(super) use user_directory::*;
pub(super) use voip::*;

/// generated device ID length
const DEVICE_ID_LENGTH: usize = 10;

/// generated user access token length
const TOKEN_LENGTH: usize = 32;

/// generated user session ID length
const SESSION_ID_LENGTH: usize = service::uiaa::SESSION_ID_LENGTH;


const AUTH_SESSION_EXPIRATION_SECS: u64 = 60 * 5;
const LOGIN_TOKEN_EXPIRATION_SECS: u64 = 15;
