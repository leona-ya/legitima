use crate::auth::User;
use crate::config::AppConfig;
use crate::error::Error;
use crate::DBLdapConn;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket::serde::Serialize;
use rocket::{Either, State};
use rocket_dyn_templates::Template;

#[get("/login")]
pub(crate) fn auth_login(_user: User, cookies: &CookieJar<'_>) -> Result<Redirect, Error> {
    let redirect_url = match cookies.get("redirect_url") {
        Some(cookie) => cookie.value().to_owned(),
        None => "/".to_owned(),
    };
    Ok(Redirect::to(redirect_url))
}

#[derive(Serialize)]
struct LoginContext {
    app_name: String,
    message: Option<String>,
}

#[get("/login", rank = 2)]
pub(crate) fn login(app_config: &State<AppConfig>) -> Template {
    let app_config = app_config.inner();
    Template::render(
        "login",
        LoginContext {
            app_name: app_config.name.clone(),
            message: None,
        },
    )
}

#[derive(FromForm)]
pub(crate) struct Login {
    username: String,
    password: String,
}

#[post("/login", data = "<form>")]
pub(crate) async fn submit(
    cookies: &CookieJar<'_>,
    ldap_conn: DBLdapConn,
    form: Form<Login>,
    app_config: &State<AppConfig>,
) -> Result<Either<Template, Redirect>, Error> {
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
        let redirect_url = match cookies.get("redirect_url") {
            Some(cookie) => cookie.value().to_owned(),
            None => "/".to_owned(),
        };

        let mut cookie = Cookie::new("username", form.username);
        cookie.set_same_site(SameSite::Lax);
        cookies.add_private(cookie);

        return Ok(Either::Right(Redirect::to(redirect_url)));
    }
    Ok(Either::Left(Template::render(
        "login",
        LoginContext {
            app_name: app_config.name.clone(),
            message: Some("Username and/or password is wrong.".to_owned()),
        },
    )))
}
