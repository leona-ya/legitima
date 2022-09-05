use crate::config::AppConfig;
use crate::db::{DBUserCredential, DB};
use crate::error::Error;
use crate::sessions::{create_session, Session, SessionStorage, User};
use crate::DBLdapConn;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket::serde::Serialize;
use rocket::{Either, State};
use rocket_db_pools::Connection;
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

async fn check_user_pw(
    ldap_conn: DBLdapConn,
    ldap_user_base_dn: String,
    username: String,
    password: String,
) -> Result<bool, Error> {
    Ok(ldap_conn
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
        .is_ok())
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
    mut db: Connection<DB>,
    mut session_storage: Connection<SessionStorage>,
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
    } else if check_user_pw(ldap_conn, ldap_user_base_dn, username, password).await? {
        let redirect_url = match cookies.get("redirect_url") {
            Some(cookie) => cookie.value().to_owned(),
            None => "/".to_owned(),
        };

        create_session(
            session_storage,
            &Session::new(form.username, true, vec!["password".to_owned()], vec![]),
            cookies,
        )
        .await?;

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
