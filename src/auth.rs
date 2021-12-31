use rocket::outcome::IntoOutcome;
use rocket::request::FromRequest;
use rocket::{request, Request};

#[derive(Debug)]
pub(crate) struct User(String);

impl User {
    pub(crate) fn get_username(self) -> String {
        self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<User, Self::Error> {
        request
            .cookies()
            .get_private("username")
            .map(|cookie| cookie.value().to_owned())
            .map(User)
            .or_forward(())
    }
}
