use ory_hydra_client::apis::configuration::Configuration;
use ory_hydra_client::models::AcceptOAuth2LoginRequest;
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket::{get, Either, State};
use rocket_dyn_templates::Template;

use crate::config::HydraConfig;
use crate::error::Error;
use crate::sessions::User;

#[get("/login?<login_challenge>")]
pub(crate) async fn auth_index(
    user: User,
    login_challenge: &str,
    hydra_config: &State<HydraConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    let hydra_configuration: &Configuration = &hydra_config.inner().as_hydra_configuration();
    let _login_request = ory_hydra_client::apis::o_auth2_api::get_o_auth2_login_request(
        hydra_configuration,
        login_challenge,
    )
    .await?;
    // let ids: Vec<String> = db_sql
    //     .run(move |conn| {
    //         db::oauth_client::table
    //             .select(db::oauth_client::client_id)
    //             .load(conn)
    //     })
    //     .await?;
    // dbg!(ids);
    let accept_login_request = ory_hydra_client::apis::o_auth2_api::accept_o_auth2_login_request(
        hydra_configuration,
        login_challenge,
        Some(AcceptOAuth2LoginRequest {
            acr: None,
            amr: None,
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
