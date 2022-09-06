use crate::config::{AppConfig, WebauthnStaticConfig};
use crate::db::{DBUserCredential, DBUserCredentialTypes, DB};
use crate::error::Error;
use crate::sessions::{create_session, Session, SessionStorage, User};
use crate::DBLdapConn;
use rocket::form::validate::Contains;
use rocket::form::Form;
use rocket::http::{CookieJar, Status};
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use rocket::{Either, State};
use rocket_db_pools::Connection;
use rocket_dyn_templates::{context, Template};
use webauthn_rs::proto::{PublicKeyCredential, RequestChallengeResponse};
use webauthn_rs::{AuthenticationState, Webauthn};

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
    session_storage: Connection<SessionStorage>,
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
        return if !DBUserCredential::find_webauthn_credentials_by_username(
            &*form.username,
            &mut *db,
        )
        .await?
        .is_empty()
        {
            create_session(
                session_storage,
                &Session::new(
                    form.username,
                    false,
                    vec!["password".to_owned()],
                    vec!["webauthn".to_owned()],
                ),
                cookies,
            )
            .await?;

            Ok(Either::Right(Redirect::to(uri!("/auth/webauthn_2fa"))))
        } else {
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

            Ok(Either::Right(Redirect::to(redirect_url)))
        };
    }
    Ok(Either::Left(Template::render(
        "login",
        LoginContext {
            app_name: app_config.name.clone(),
            message: Some("Username and/or password is wrong.".to_owned()),
        },
    )))
}

#[get("/webauthn_2fa")]
pub(crate) fn webauthn_2fa(
    session: Session,
    app_config: &State<AppConfig>,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    if !session.missing_auth_steps.contains("webauthn".to_owned()) {
        return Err(Error::Http(Status::NotFound));
    };
    Ok(Template::render(
        "webauthn_auth",
        context! {
           app_name: app_config.name.clone()
        },
    ))
    // session.finish_step("webauthn");
}

#[derive(Serialize)]
pub(crate) struct WebAuthnChallengeLoginResponse {
    id: uuid::Uuid,
    cc: RequestChallengeResponse,
}

#[get("/webauthn_2fa/challenge_login", format = "json")]
pub(crate) async fn webauthn_2fa_challenge_login(
    session: Session,
    webauthn_static_config: &State<WebauthnStaticConfig>,
    mut db: Connection<DB>,
) -> Result<Json<WebAuthnChallengeLoginResponse>, Error> {
    let webauthn_static_config = webauthn_static_config.inner().clone();
    let webauthn_client = Webauthn::new(webauthn_static_config);
    let webauthn_credentials =
        DBUserCredential::find_webauthn_credentials_by_username(&*session.username, &mut *db)
            .await?
            .iter()
            .map(|c| c.credential_data.0.clone())
            .collect();
    match webauthn_client.generate_challenge_authenticate(webauthn_credentials) {
        Ok((webauthn_challenge, webauthn_authentication_state)) => {
            let db_row_id = DBUserCredential::create_one(
                DBUserCredential {
                    id: None,
                    label: None,
                    username: session.username,
                    credential_type: DBUserCredentialTypes::WebauthnAuthentication,
                    credential_data: sqlx::types::Json(webauthn_authentication_state),
                },
                &mut *db,
            )
            .await?;
            Ok(Json(WebAuthnChallengeLoginResponse {
                id: db_row_id,
                cc: webauthn_challenge,
            }))
        }
        Err(_) => Err(Error::Http(Status::InternalServerError)),
    }
}

#[post(
    "/webauthn_2fa/login/<credential_id>",
    format = "json",
    data = "<cred>"
)]
pub(crate) async fn webauthn_2fa_login(
    session: Session,
    credential_id: uuid::Uuid,
    cred: Json<PublicKeyCredential>,
    webauthn_static_config: &State<WebauthnStaticConfig>,
    mut db: Connection<DB>,
    session_storage: Connection<SessionStorage>,
    cookies: &CookieJar<'_>,
) -> Result<String, Error> {
    let webauthn_static_config = webauthn_static_config.inner().clone();
    let webauthn_client = Webauthn::new(webauthn_static_config);
    let authentication_state =
        DBUserCredential::<AuthenticationState>::find_webauthn_authentication_by_id_and_username(
            credential_id,
            &*session.username,
            &mut *db,
        )
        .await?
        .credential_data
        .0;
    DBUserCredential::<AuthenticationState>::delete_credential(
        credential_id,
        &*session.username,
        &mut *db,
    )
    .await?;
    match webauthn_client.authenticate_credential(&cred.into_inner(), &authentication_state) {
        Ok((_cid, _credential)) => {
            let redirect_url = match cookies.get("redirect_url") {
                Some(cookie) => cookie.value().to_owned(),
                None => "/".to_owned(),
            };
            // dbg!(credential.counter);
            // DBUserCredential::<Credential>::update_counter(cid, credential.counter, &mut *db)
            //     .await?;
            session.finish_step("webauthn", session_storage).await?;
            Ok(redirect_url)
        }
        Err(_) => Err(Error::Http(Status::InternalServerError)),
    }
}
