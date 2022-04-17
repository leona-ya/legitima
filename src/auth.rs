use crate::config::AppConfig;
use crate::ldap::get_user_groups;
use crate::DBLdapConn;
use rocket::form::validate::Contains;
use rocket::outcome::IntoOutcome;
use rocket::request::FromRequest;
use rocket::{request, Request};

#[derive(Debug)]
pub(crate) struct CookieUser(String);

impl CookieUser {
    pub(crate) fn get_username(self) -> String {
        self.0
    }

    pub(crate) async fn is_admin(
        &self,
        app_config: &AppConfig,
        ldap_conn: &DBLdapConn,
    ) -> Result<bool, crate::error::Error> {
        let user_groups = get_user_groups(app_config, ldap_conn, &self.0).await;
        Ok(user_groups?.contains(app_config.ldap_admin_group_dn.clone()))
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CookieUser {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<CookieUser, Self::Error> {
        request
            .cookies()
            .get_private("username")
            .map(|cookie| cookie.value().to_owned())
            .map(CookieUser)
            .or_forward(())
    }
}
