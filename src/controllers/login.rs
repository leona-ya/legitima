use ory_hydra_client::apis::configuration::Configuration;
use ory_hydra_client::models::AcceptLoginRequest;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket::{get, Either, State};
use rocket_dyn_templates::Template;
use serde::Serialize;

use crate::auth::User;
use crate::config::{AppConfig, HydraConfig};
use crate::error::Error;
use crate::DBLdapConn;

async fn handle_login(
    user: Option<User>,
    login_challenge: &str,
    hydra_config: &State<HydraConfig>,
    app_config: &State<AppConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    let hydra_configuration: &Configuration = &hydra_config.inner().into_hydra_configuration();
    let app_config = app_config.inner();
    ory_hydra_client::apis::admin_api::get_login_request(hydra_configuration, login_challenge)
        .await?;

    if let Some(user_record) = user {
        let accept_login_request = ory_hydra_client::apis::admin_api::accept_login_request(
            hydra_configuration,
            login_challenge,
            Some(AcceptLoginRequest {
                acr: None,
                context: None,
                force_subject_identifier: None,
                remember: None,
                remember_for: None,
                subject: user_record.get_username(),
            }),
        )
        .await?;

        return Ok(Either::Right(Redirect::to(
            accept_login_request.redirect_to,
        )));
    }

    Ok(Either::Left(Template::render(
        "login",
        LoginContext {
            app_name: app_config.name.clone(),
            message: None,
            login_challenge: login_challenge.to_owned(),
        },
    )))
}

#[get("/?<login_challenge>")]
pub async fn auth_index(
    user: User,
    login_challenge: &str,
    hydra_config: &State<HydraConfig>,
    app_config: &State<AppConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    handle_login(Some(user), login_challenge, hydra_config, app_config).await
}

#[get("/?<login_challenge>", rank = 2)]
pub async fn index(
    login_challenge: &str,
    hydra_config: &State<HydraConfig>,
    app_config: &State<AppConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    handle_login(None, login_challenge, hydra_config, app_config).await
}

#[derive(FromForm)]
pub struct Login {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginContext {
    app_name: String,
    message: Option<String>,
    login_challenge: String,
}

#[post("/?<login_challenge>", data = "<form>")]
pub async fn submit<'r>(
    cookie_jar: &CookieJar<'_>,
    ldap_conn: DBLdapConn,
    form: Form<Login>,
    login_challenge: &str,
    hydra_config: &State<HydraConfig>,
    app_config: &State<AppConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    let hydra_configuration: &Configuration = &hydra_config.inner().into_hydra_configuration();
    let app_config = app_config.inner();
    let form = form.into_inner();
    let username = form.username.clone();
    let password = form.password.clone();
    let ldap_user_base_dn = app_config.ldap_user_base_dn.clone();
    if form.username.is_empty() || form.password.is_empty() {
        return Ok(Either::Left(Template::render(
            "login",
            LoginContext {
                app_name: app_config.name.clone(),
                message: Some("Username and password cannot be empty".to_owned()),
                login_challenge: login_challenge.to_owned(),
            },
        )));
    } else if ldap_conn
        .run(move |c| {
            let bind = c.simple_bind(
                &*format!("uid={},{}", username, ldap_user_base_dn),
                &*password,
            );
            c.unbind(); // TODO: Handle error
            bind
        })
        .await?
        .success()
        .is_ok()
    {
        let accept_login_request = ory_hydra_client::apis::admin_api::accept_login_request(
            hydra_configuration,
            login_challenge,
            Some(AcceptLoginRequest {
                acr: None,
                context: None,
                force_subject_identifier: None,
                remember: None,
                remember_for: None,
                subject: form.username.clone(),
            }),
        )
        .await?;
        let mut cookie = Cookie::new("username", form.username);
        cookie.set_same_site(SameSite::Lax);
        cookie_jar.add_private(cookie);
        return Ok(Either::Right(Redirect::to(
            accept_login_request.redirect_to,
        )));
    }
    Ok(Either::Left(Template::render(
        "login",
        LoginContext {
            app_name: app_config.name.clone(),
            message: Some("Username and/or password is wrong.".to_owned()),
            login_challenge: login_challenge.to_owned(),
        },
    )))
}
