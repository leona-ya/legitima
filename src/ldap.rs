use rocket::http::Status;
use std::collections::{HashMap, HashSet};

use crate::config::AppConfig;
use crate::error::Error;
use crate::DBLdapConn;
use rocket::serde::Serialize;

#[derive(Serialize)]
pub(crate) struct LDAPUser {
    pub(crate) username: String,
    pub(crate) name: String,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
    pub(crate) email: String,
}

fn format_user_dn(app_config: &AppConfig, username: &str) -> String {
    format!("uid={},{}", username, app_config.ldap_user_base_dn)
}

async fn change_attrs(
    ldap_conn: DBLdapConn,
    dn: String,
    changes: Vec<(String, String)>,
) -> Result<ldap3::LdapResult, ldap3::LdapError> {
    let mods: Vec<ldap3::Mod<String>> = changes
        .iter()
        .map(|(attr, change)| ldap3::Mod::Replace(attr.clone(), HashSet::from([change.clone()])))
        .collect();
    ldap_conn.run(move |c| c.modify(&dn, mods)).await?.success()
}

pub(crate) async fn change_user_attrs(
    app_config: &AppConfig,
    ldap_conn: DBLdapConn,
    username: &str,
    changes: Vec<(String, String)>,
) -> Result<ldap3::LdapResult, ldap3::LdapError> {
    change_attrs(ldap_conn, format_user_dn(app_config, username), changes).await
}

pub(crate) async fn get_ldap_user(
    app_config: &AppConfig,
    ldap_conn: DBLdapConn,
    username: &str,
) -> Result<LDAPUser, Error> {
    let user_attrs = get_dn_attrs(ldap_conn, format_user_dn(app_config, username.clone())).await?;
    Ok(LDAPUser {
        username: username.to_owned(),
        name: user_attrs
            .get("displayName")
            .unwrap_or(&vec!["".to_owned()])
            .first()
            .unwrap()
            .clone(),
        first_name: user_attrs
            .get("cn")
            .unwrap_or(&vec!["".to_owned()])
            .first()
            .unwrap()
            .clone(),
        last_name: user_attrs
            .get("sn")
            .unwrap_or(&vec!["".to_owned()])
            .first()
            .unwrap()
            .clone(),
        email: user_attrs
            .get("mail")
            .unwrap_or(&vec!["".to_owned()])
            .first()
            .unwrap()
            .clone(),
    })
}

async fn get_dn_attrs(
    ldap_conn: DBLdapConn,
    dn: String,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let (ldap_search_rs, _) = ldap_conn
        .run(move |c| {
            c.search(
                &dn,
                ldap3::Scope::Base,
                "objectClass=inetOrgPerson",
                vec!["*"],
            )
        })
        .await?
        .success()?;

    if let Some(ldap_search) = ldap_search_rs.into_iter().next() {
        Ok(ldap3::SearchEntry::construct(ldap_search).attrs)
    } else {
        Err(Error::Http(Status::InternalServerError))
    }
}
