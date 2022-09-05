use crate::config::WebauthnStaticConfig;
use crate::db::{DBUserCredential, DBUserCredentialTypes, DB};
use crate::error::Error;
use crate::sessions::User;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::State;
use rocket_db_pools::Connection;
use rocket_dyn_templates::Template;
use serde::{Deserialize, Serialize};
use webauthn_rs::proto::{
    CreationChallengeResponse, Credential, CredentialID, RegisterPublicKeyCredential,
};
use webauthn_rs::{RegistrationState, Webauthn};

#[get("/security", rank = 2)]
pub(crate) async fn get_security(cookies: &CookieJar<'_>) -> Redirect {
    cookies.add(Cookie::new(
        "redirect_url",
        uri!("/selfservice", auth_get_security()).to_string(),
    ));
    Redirect::to(uri!("/auth", crate::controllers::auth::login::login()))
}

#[derive(Serialize)]
struct SecurityHomeContext {
    webauthn_credentials: Vec<(uuid::Uuid, String)>,
}

#[get("/security")]
pub(crate) async fn auth_get_security(
    cookie_user: User,
    mut db: Connection<DB>,
) -> Result<Template, Error> {
    let username = cookie_user.get_username();
    let webauthn_credentials =
        DBUserCredential::find_webauthn_credentials_by_username(&*username, &mut *db).await?;
    Ok(Template::render(
        "selfservice/security",
        SecurityHomeContext {
            webauthn_credentials: webauthn_credentials
                .iter()
                .map(|c| {
                    (
                        c.id.unwrap(),
                        c.label.as_ref().unwrap_or(&"".to_string()).clone(),
                    )
                })
                .collect(),
        },
    ))
}

#[get("/security/credential/<credential_id>/delete")]
pub(crate) async fn auth_credential_delete(
    cookie_user: User,
    credential_id: uuid::Uuid,
    mut db: Connection<DB>,
) -> Result<Redirect, Error> {
    DBUserCredential::<Credential>::delete_credential(
        credential_id,
        &*cookie_user.get_username(),
        &mut *db,
    )
    .await?;
    Ok(Redirect::to(uri!("/selfservice", auth_get_security())))
}

// ################### WebAuthn ################### //

#[derive(Deserialize, Debug)]
pub(crate) struct WebAuthnChallengeRegisterBody {
    pub label: String,
}

#[derive(Serialize)]
pub(crate) struct WebAuthnChallengeRegisterResponse {
    id: uuid::Uuid,
    cc: CreationChallengeResponse,
}

#[post(
    "/security/webauthn/challenge_register",
    format = "json",
    data = "<body>"
)]
pub(crate) async fn auth_webauthn_challenge_register(
    body: Json<WebAuthnChallengeRegisterBody>,
    cookie_user: User,
    webauthn_static_config: &State<WebauthnStaticConfig>,
    mut db: Connection<DB>,
) -> Result<Json<WebAuthnChallengeRegisterResponse>, Error> {
    let webauthn_static_config = webauthn_static_config.inner().clone();
    let webauthn_client = Webauthn::new(webauthn_static_config);
    let cookie_username = cookie_user.get_username().clone();
    dbg!(&body);
    match webauthn_client.generate_challenge_register(&*cookie_username, false) {
        Ok((webauthn_challenge, webauthn_registration_state)) => {
            let db_row_id = DBUserCredential::create_one(
                DBUserCredential {
                    id: None,
                    // label: None,
                    label: Some(body.label.clone()),
                    username: cookie_username,
                    credential_type: DBUserCredentialTypes::WebauthnRegistration,
                    credential_data: sqlx::types::Json(webauthn_registration_state),
                },
                &mut *db,
            )
            .await?;
            Ok(Json(WebAuthnChallengeRegisterResponse {
                id: db_row_id,
                cc: webauthn_challenge,
            }))
        }
        Err(e) => Err(Error::Http(Status::InternalServerError)),
    }
}
#[post(
    "/security/webauthn/register/<credential_id>",
    format = "json",
    data = "<reg>"
)]
pub(crate) async fn auth_webauthn_register(
    cookie_user: User,
    credential_id: uuid::Uuid,
    reg: Json<RegisterPublicKeyCredential>,
    webauthn_static_config: &State<WebauthnStaticConfig>,
    mut db: Connection<DB>,
) -> Result<(), Error> {
    let webauthn_static_config = webauthn_static_config.inner().clone();
    let webauthn_client = Webauthn::new(webauthn_static_config);
    let cookie_username = &*cookie_user.get_username();
    let registration_state =
        DBUserCredential::<RegistrationState>::find_webauthn_registration_by_id_and_username(
            credential_id,
            cookie_username,
            &mut *db,
        )
        .await?
        .credential_data
        .0;
    let user_webauthn_credentials =
        DBUserCredential::find_webauthn_credentials_by_username(cookie_username, &mut *db).await?;
    let user_webauthn_credential_ids: Vec<CredentialID> = user_webauthn_credentials
        .iter()
        .map(|v| v.credential_data.cred_id.clone())
        .collect();
    match webauthn_client.register_credential(&reg.into_inner(), &registration_state, |cid| {
        Ok(user_webauthn_credential_ids.contains(cid))
    }) {
        Ok((webauthn_credential, _)) => {
            DBUserCredential::update_type_data(
                credential_id,
                DBUserCredentialTypes::WebauthnCredential,
                sqlx::types::Json(webauthn_credential),
                &mut *db,
            )
            .await?;
            Ok(())
        }
        Err(_) => Err(Error::Http(Status::InternalServerError)),
    }
}
