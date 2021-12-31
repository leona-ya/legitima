use ory_hydra_client::apis::configuration::Configuration;
use ory_hydra_client::models::AcceptLoginRequest;
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket::{get, Either, State};
use rocket_dyn_templates::Template;

use crate::auth::User;
use crate::config::HydraConfig;
use crate::error::Error;

#[get("/login?<login_challenge>")]
pub(crate) async fn auth_index(
    user: User,
    login_challenge: &str,
    hydra_config: &State<HydraConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    let hydra_configuration: &Configuration = &hydra_config.inner().into_hydra_configuration();
    ory_hydra_client::apis::admin_api::get_login_request(hydra_configuration, login_challenge)
        .await?;
    let accept_login_request = ory_hydra_client::apis::admin_api::accept_login_request(
        hydra_configuration,
        login_challenge,
        Some(AcceptLoginRequest {
            acr: None,
            context: None,
            force_subject_identifier: None,
            remember: None,
            remember_for: None,
            subject: user.get_username(),
        }),
    )
    .await?;

    Ok(Either::Right(Redirect::to(
        accept_login_request.redirect_to,
    )))
}

#[get("/login?<login_challenge>", rank = 2)]
pub(crate) async fn index(login_challenge: &str, cookies: &CookieJar<'_>) -> Redirect {
    cookies.add(Cookie::new(
        "redirect_url",
        uri!("/oidc", auth_index(login_challenge)).to_string(),
    ));
    Redirect::to(uri!("/auth", crate::controllers::auth::login::login()))
}
