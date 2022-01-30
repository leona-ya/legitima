use rocket::outcome::IntoOutcome;
use rocket::request::FromRequest;
use rocket::{request, Request};

#[derive(Debug)]
pub(crate) struct CookieUser(String);

impl CookieUser {
    pub(crate) fn get_username(self) -> String {
        self.0
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
