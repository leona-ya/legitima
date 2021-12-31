use std::collections::HashMap;

use ory_hydra_client::apis::configuration::Configuration;
use ory_hydra_client::models::{
    AcceptConsentRequest, ConsentRequest, ConsentRequestSession, RejectRequest,
};
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::{get, Either, State};
use rocket_dyn_templates::Template;
use serde::Serialize;
use serde_json::json;

use crate::config::{AppConfig, HydraConfig};
use crate::error::Error;
use crate::DBLdapConn;

#[derive(Serialize, Clone)]
struct Scope {
    name: &'static str,
    short_description: &'static str,
    description: &'static str,
    ldap_fields: Vec<(&'static str, &'static str)>,
    icon: &'static str,
}

fn get_scopes() -> HashMap<&'static str, Scope> {
    HashMap::from([
        (
            "email",
            Scope {
                name: "email",
                short_description: "View your email address",
                description: "The service gets access to your email address",
                ldap_fields: vec![("email", "mail")],
                icon: "openmoji/email.svg",
            },
        ),
        (
            "profile",
            Scope {
                name: "profile",
                short_description: "Get your general profile information",
                description: "The service gets access to general information of your profile",
                ldap_fields: vec![
                    ("name", "displayName"),
                    ("given_name", "cn"),
                    ("family_name", "sn"),
                    ("preferred_username", "uid"),
                ],
                icon: "openmoji/person.svg",
            },
        ),
    ])
}

#[derive(Serialize)]
struct ConsentContext {
    app_name: String,
    message: Option<String>,
    consent_challenge: String,
    client_name: String,
    client_uri: String,
    requested_scopes: Vec<Scope>,
}

#[get("/consent?<consent_challenge>")]
pub(crate) async fn index(
    ldap_conn: DBLdapConn,
    consent_challenge: &str,
    hydra_config: &State<HydraConfig>,
    app_config: &State<AppConfig>,
) -> Result<Either<Template, Redirect>, Error> {
    let app_config = app_config.inner();
    let hydra_configuration: &Configuration = &hydra_config.inner().into_hydra_configuration();
    let consent_request = ory_hydra_client::apis::admin_api::get_consent_request(
        hydra_configuration,
        consent_challenge,
    )
    .await?;

    if let Some(skip) = consent_request.skip {
        if skip {
            return match accept_consent_request(
                ldap_conn,
                hydra_config.inner(),
                hydra_configuration,
                consent_challenge,
                consent_request,
                app_config,
            )
            .await
            {
                Ok(redirect) => Ok(Either::Right(redirect)),
                Err(error) => Err(error),
            };
        }
    }

    let requested_scope_details: Vec<Scope> = consent_request
        .requested_scope
        .unwrap()
        .iter()
        .map(|scope| get_scopes().get(scope as &str).cloned())
        .flatten()
        .collect();

    let client = consent_request.client.unwrap();

    Ok(Either::Left(Template::render(
        "consent",
        ConsentContext {
            app_name: app_config.name.clone(),
            message: None,
            consent_challenge: consent_challenge.to_owned(),
            client_name: client.client_name.unwrap(),
            client_uri: client.client_uri.unwrap_or_else(|| "".to_owned()),
            requested_scopes: requested_scope_details,
        },
    )))
}

#[get("/consent/approve?<consent_challenge>")]
pub(crate) async fn approve(
    ldap_conn: DBLdapConn,
    consent_challenge: &str,
    hydra_config: &State<HydraConfig>,
    app_config: &State<AppConfig>,
) -> Result<Redirect, Error> {
    let hydra_configuration: &Configuration = &hydra_config.inner().into_hydra_configuration();
    let app_config = app_config.inner();
    let consent_request = ory_hydra_client::apis::admin_api::get_consent_request(
        hydra_configuration,
        consent_challenge,
    )
    .await?;

    accept_consent_request(
        ldap_conn,
        hydra_config.inner(),
        hydra_configuration,
        consent_challenge,
        consent_request,
        app_config,
    )
    .await
}

#[get("/consent/reject?<consent_challenge>")]
pub(crate) async fn reject(
    consent_challenge: &str,
    hydra_config: &State<HydraConfig>,
) -> Result<Redirect, Error> {
    let hydra_configuration: &Configuration = &hydra_config.inner().into_hydra_configuration();
    let reject_consent_request = ory_hydra_client::apis::admin_api::reject_consent_request(
        hydra_configuration,
        consent_challenge,
        Some(RejectRequest {
            error: Some("access_denied".to_owned()),
            error_debug: None,
            error_description: Some("The user rejected the request.".to_owned()),
            error_hint: None,
            status_code: None,
        }),
    )
    .await?;
    Ok(Redirect::to(reject_consent_request.redirect_to))
}
async fn accept_consent_request(
    ldap_conn: DBLdapConn,
    hydra_config: &HydraConfig,
    hydra_configuration: &Configuration,
    consent_challenge: &str,
    consent_request: ConsentRequest,
    app_config: &AppConfig,
) -> Result<Redirect, Error> {
    let ldap_user_base_dn = app_config.ldap_user_base_dn.clone();
    let (ldap_search_rs, _) = ldap_conn
        .run(move |c| {
            c.search(
                &*format!(
                    "uid={},{}",
                    consent_request.subject.unwrap(),
                    ldap_user_base_dn
                ),
                ldap3::Scope::Base,
                "objectClass=inetOrgPerson",
                vec!["*"],
            )
        })
        .await?
        .success()?;
    let ldap_user_data: ldap3::SearchEntry;

    if let Some(ldap_search_user) = ldap_search_rs.into_iter().next() {
        ldap_user_data = ldap3::SearchEntry::construct(ldap_search_user);
    } else {
        return Err(Error::Http(Status::BadRequest));
    }

    let accept_consent_request = ory_hydra_client::apis::admin_api::accept_consent_request(
        hydra_configuration,
        consent_challenge,
        Some(AcceptConsentRequest {
            grant_access_token_audience: consent_request.requested_access_token_audience,
            grant_scope: consent_request.requested_scope.clone(),
            handled_at: Some(chrono::Utc::now().to_rfc3339()),
            remember: Some(hydra_config.consent_remember_me),
            remember_for: Some(hydra_config.consent_remember_me_for),
            session: Some(Box::new(data_to_session(
                ldap_user_data,
                consent_request.requested_scope.unwrap(),
            ))),
        }),
    )
    .await?;
    Ok(Redirect::to(accept_consent_request.redirect_to))
}

fn data_to_session(ldap_user: ldap3::SearchEntry, scopes: Vec<String>) -> ConsentRequestSession {
    let mut consent_request_session = ConsentRequestSession::new();
    let mut id_token_data = HashMap::new();
    let default_vec: Vec<String> = Vec::new();
    let default_str = String::new();

    for scope in &scopes {
        if let Some(scope_data) = get_scopes().get(scope as &str) {
            for ldap_fieldpair in &scope_data.ldap_fields {
                id_token_data.insert(
                    ldap_fieldpair.0,
                    &**ldap_user
                        .attrs
                        .get(ldap_fieldpair.1)
                        .unwrap_or(&default_vec)
                        .first()
                        .unwrap_or(&default_str),
                );
            }
        }
    }
    consent_request_session.id_token = Some(json!(id_token_data));
    consent_request_session
}
