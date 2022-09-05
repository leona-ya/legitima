use crate::config::AppConfig;
use crate::error::Error;
use crate::ldap::get_user_groups;
use crate::DBLdapConn;
use hmac::{Hmac, Mac};
use rand::Rng;
use rocket::form::validate::Contains;
use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::outcome::{try_outcome, IntoOutcome};
use rocket::request::{FromRequest, Outcome};
use rocket::{request, Request};
use rocket_db_pools::deadpool_redis::redis::AsyncCommands;
use rocket_db_pools::{deadpool_redis, Connection, Database};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Database)]
#[database("session_storage")]
pub(crate) struct SessionStorage(deadpool_redis::Pool);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Session {
    #[serde(skip_serializing)]
    id: Option<String>,
    username: String,
    auth_timestamp: String,
    fully_authenticated: bool,
    completed_auth_steps: Vec<String>,
    missing_auth_steps: Vec<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Session {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Session, Self::Error> {
        let r = request.guard::<Connection<SessionStorage>>().await;
        let session_storage = match r {
            Outcome::Success(sess) => sess,
            Outcome::Failure(_) | Outcome::Forward(_) => return Outcome::Forward(()),
        };
        if let Some(cookie_value) = request
            .cookies()
            .get("legitima_session")
            .map(|cookie| cookie.value().to_owned())
        {
            if let Ok(Some(session)) = validate_session(session_storage, cookie_value).await {
                return Outcome::Success(session);
            }
        }
        return Outcome::Forward(());
    }
}

impl Session {
    pub fn new(
        username: String,
        fully_authenticated: bool,
        completed_auth_steps: Vec<String>,
        missing_auth_steps: Vec<String>,
    ) -> Session {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const PASSWORD_LEN: usize = 32;
        let mut rng = rand::thread_rng();

        let session_id: String = (0..PASSWORD_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        Session {
            id: Some(session_id),
            username,
            auth_timestamp: chrono::Utc::now().to_rfc3339(),
            fully_authenticated,
            completed_auth_steps,
            missing_auth_steps,
        }
    }
}

pub(crate) async fn create_session(
    mut session_storage: Connection<SessionStorage>,
    session: &Session,
    cookies: &CookieJar<'_>,
) -> Result<(), Error> {
    let conn = &mut *session_storage;
    let session_string = serde_json::to_string(session)?;
    let session_id = match &session.id {
        Some(id) => id,
        None => return Err(Error::Http(Status::InternalServerError)),
    };
    conn.set(session_id, session_string).await?;

    let mut mac = HmacSha256::new_from_slice(b"my secret and secure key").unwrap();
    mac.update(session_id.as_bytes());
    let mac_result = mac.finalize().into_bytes();

    let cookie_value = session_id.clone() + "." + &*hex::encode(mac_result);
    let mut cookie = Cookie::new("legitima_session", cookie_value);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(true);
    cookies.add(cookie);
    Ok(())
}

async fn validate_session(
    mut session_storage: Connection<SessionStorage>,
    cookie_value: String,
) -> Result<Option<Session>, Error> {
    fn validate_hmac(session_id: &str, hex_session_hmac_code: &str) -> Option<()> {
        let mut mac = HmacSha256::new_from_slice(b"my secret and secure key").unwrap();
        mac.update(session_id.as_bytes());
        let session_hmac_code = match hex::decode(hex_session_hmac_code) {
            Ok(code) => code,
            Err(_) => return None,
        };
        match mac.verify_slice(&session_hmac_code) {
            Ok(_) => Some(()),
            Err(_) => None,
        }
    }

    let mut cookie_value_iter = cookie_value.split('.');
    let session_id = match cookie_value_iter.next() {
        Some(id) => id,
        None => return Ok(None),
    };
    let session_hmac_code = match cookie_value_iter.next() {
        Some(code) => code,
        None => return Ok(None),
    };

    if validate_hmac(session_id, session_hmac_code).is_none() {
        return Ok(None);
    }

    let conn = &mut *session_storage;
    let session_data: String = conn.get(session_id).await?;
    Ok(Some(serde_json::from_str::<Session>(&session_data[..])?))
}

pub(crate) struct User(String);

impl User {
    pub(crate) fn get_username(self) -> String {
        self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<User, Self::Error> {
        let session = try_outcome!(request.guard::<Session>().await);

        Outcome::Success(User(session.username))
    }
}

pub(crate) struct AdminUser(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<AdminUser, Self::Error> {
        let user = try_outcome!(request.guard::<User>().await);
        let r = request.guard::<DBLdapConn>().await;
        let ldap_conn = match r {
            Outcome::Success(conn) => conn,
            _ => return Outcome::Forward(()),
        };
        let app_config = request.rocket().state::<AppConfig>().unwrap();

        let user_groups = match get_user_groups(app_config, &ldap_conn, &user.0).await {
            Ok(groups) => groups,
            Err(_) => return Outcome::Forward(()),
        };
        match user_groups.contains(app_config.ldap_admin_group_dn.clone()) {
            true => Outcome::Success(AdminUser(user.0)),
            false => Outcome::Forward(()),
        }
    }
}
