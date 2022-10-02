use crate::config::{AppConfig, WebauthnStaticConfig};
use crate::db::{DBTotpCredential, DBUserCredential, DBUserCredentialTypes, DB};
use crate::error::Error;
use crate::sessions::User;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::{Either, State};
use rocket_db_pools::Connection;
use rocket_dyn_templates::{context, Template};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
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
    totp_credentials: Vec<(uuid::Uuid, String)>,
}

#[get("/security")]
pub(crate) async fn auth_get_security(
    cookie_user: User,
    mut db: Connection<DB>,
) -> Result<Template, Error> {
    let username = cookie_user.get_username();
    let webauthn_credentials =
        DBUserCredential::find_webauthn_credentials_by_username(&*username, &mut *db).await?;
    let totp_credentials =
        DBUserCredential::find_totp_credentials_by_username(&*username, &mut *db).await?;
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
            totp_credentials: totp_credentials
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
                    temporary: true,
                },
                &mut *db,
            )
            .await?;
            Ok(Json(WebAuthnChallengeRegisterResponse {
                id: db_row_id,
                cc: webauthn_challenge,
            }))
        }
        Err(_) => Err(Error::Http(Status::InternalServerError)),
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
                false,
                &mut *db,
            )
            .await?;
            Ok(())
        }
        Err(_) => Err(Error::Http(Status::InternalServerError)),
    }
}

// ################### TOTP ################### //

#[get("/security/totp/setup/step1")]
pub(crate) async fn auth_totp_setup_step1(_user: User, app_config: &State<AppConfig>) -> Template {
    let app_config = app_config.inner();
    Template::render(
        "selfservice/security_totp_setup_step1",
        context! {
            app_name: app_config.name.clone()
        },
    )
}

#[derive(FromForm, Debug)]
pub(crate) struct TOTPSetupStep1Form {
    #[field(validate = len(1..))]
    label: String,
}

#[post("/security/totp/setup/step2", data = "<form>")]
pub(crate) async fn auth_totp_setup_step2(
    user: User,
    app_config: &State<AppConfig>,
    form: Form<TOTPSetupStep1Form>,
    mut db: Connection<DB>,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let secret = totp_rs::Secret::generate_secret();
    let algorithm = Algorithm::SHA256;
    let username = user.get_username();
    let totp = TOTP::new(
        algorithm,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some(app_config.name.clone()),
        username.clone(),
    )
    .unwrap();
    let totp_db_id = DBUserCredential::create_one(
        DBUserCredential {
            id: None,
            label: Some(form.into_inner().label.clone()),
            username,
            credential_type: DBUserCredentialTypes::TotpCredential,
            credential_data: sqlx::types::Json(DBTotpCredential {
                algorithm,
                secret: secret.to_encoded().to_string(),
            }),
            temporary: false,
        },
        &mut *db,
    )
    .await?;
    let totp_qr = totp.get_qr()?;
    Ok(Template::render(
        "selfservice/security_totp_setup_step2",
        context! {
            app_name: app_config.name.clone(),
            totp_secret: secret.to_encoded().to_string(),
            totp_qr: totp_qr,
            totp_db_id
        },
    ))
}

#[derive(FromForm, Debug)]
pub(crate) struct TOTPSetupStep2Form {
    db_id: uuid::Uuid,
    otp: usize,
}

#[post("/security/totp/setup/step3", data = "<form>")]
pub(crate) async fn auth_totp_setup_step3(
    user: User,
    app_config: &State<AppConfig>,
    form: Form<TOTPSetupStep2Form>,
    mut db: Connection<DB>,
) -> Result<Either<Redirect, Template>, Error> {
    let form = form.into_inner();
    let username = user.get_username();
    let totp_credential = DBUserCredential::find_totp_credentials_by_id_and_username(
        form.db_id, &*username, &mut *db,
    )
    .await?;
    let totp = match TOTP::new(
        totp_credential.credential_data.algorithm,
        6,
        1,
        30,
        Secret::Encoded(totp_credential.credential_data.secret.clone())
            .to_bytes()
            .unwrap(),
        Some(app_config.name.clone()),
        username,
    ) {
        Ok(totp) => totp,
        Err(_) => return Err(Error::Http(Status::InternalServerError)),
    };
    if totp.check_current(&*form.otp.to_string())? {
        DBUserCredential::<DBTotpCredential>::update_temporary(form.db_id, false, &mut *db).await?;
        Ok(Either::Left(Redirect::to(uri!(
            "/selfservice",
            auth_get_security()
        ))))
    } else {
        Ok(Either::Right(Template::render(
            "selfservice/security_totp_setup_step2",
            context! {
                app_name: app_config.name.clone(),
                totp_secret: totp_credential.credential_data.secret.clone(),
                totp_qr: totp.get_qr()?,
                totp_db_id: form.db_id,
                otp_error: true,
            },
        )))
    }
}
