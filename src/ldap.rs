use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use rocket::http::Status;
use rocket::serde::Serialize;

use crate::config::AppConfig;
use crate::error::Error;
use crate::DBLdapConn;

#[derive(Serialize)]
pub(crate) struct LDAPUser {
    pub(crate) username: String,
    pub(crate) name: String,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
    pub(crate) email: String,
}

pub(crate) fn format_user_dn(app_config: &AppConfig, username: &str) -> String {
    format!("uid={},{}", username, app_config.ldap_user_base_dn)
}

pub(crate) async fn change_attrs<S: 'static + AsRef<[u8]> + Eq + Hash + Send>(
    ldap_conn: &DBLdapConn,
    dn: String,
    changes: Vec<ldap3::Mod<S>>,
) -> Result<ldap3::LdapResult, ldap3::LdapError> {
    ldap_conn
        .run(move |c| c.modify(&dn, changes))
        .await?
        .success()
}

pub(crate) async fn get_all_users(
    app_config: &AppConfig,
    ldap_conn: &DBLdapConn,
) -> Result<Vec<String>, Error> {
    let users_base_dn = app_config.ldap_user_base_dn.clone();
    let (ldap_search_rs, _) = ldap_conn
        .run(move |c| {
            c.search(
                &users_base_dn,
                ldap3::Scope::Subtree,
                "objectClass=inetOrgPerson",
                vec!["*"],
            )
        })
        .await?
        .success()?;

    let mut result = Vec::new();
    for entry in ldap_search_rs {
        let search_entry = ldap3::SearchEntry::construct(entry);
        result.push(search_entry.dn);
    }
    result.sort();
    Ok(result)
}

pub(crate) async fn get_ldap_user(
    app_config: &AppConfig,
    ldap_conn: &DBLdapConn,
    username: &str,
) -> Result<LDAPUser, Error> {
    let user_attrs = get_dn_attrs(
        ldap_conn,
        format_user_dn(app_config, username),
        "inetOrgPerson",
    )
    .await?;
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
    ldap_conn: &DBLdapConn,
    dn: String,
    object_class: &'static str,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let (ldap_search_rs, _) = ldap_conn
        .run(move |c| {
            c.search(
                &dn,
                ldap3::Scope::Base,
                &format!("objectClass={}", object_class),
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

pub(crate) async fn get_user_groups(
    app_config: &AppConfig,
    ldap_conn: &DBLdapConn,
    username: &str,
) -> Result<Vec<String>, Error> {
    let user_dn = format_user_dn(app_config, username);
    let groups_base_dn = app_config.ldap_groups_base_dn.clone();
    let (ldap_search_rs, _) = ldap_conn
        .run(move |c| {
            c.search(
                &groups_base_dn,
                ldap3::Scope::OneLevel,
                &format!("(&(objectClass=groupOfNames)(member={}))", user_dn),
                vec!["l"],
            )
        })
        .await?
        .success()?;

    let mut result = Vec::new();
    for entry in ldap_search_rs {
        result.push(ldap3::SearchEntry::construct(entry).dn)
    }
    Ok(result)
}

pub(crate) async fn get_all_groups(
    app_config: &AppConfig,
    ldap_conn: &DBLdapConn,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let groups_base_dn = app_config.ldap_groups_base_dn.clone();
    let (ldap_search_rs, _) = ldap_conn
        .run(move |c| {
            c.search(
                &groups_base_dn,
                ldap3::Scope::Subtree,
                "objectClass=groupOfNames",
                vec!["*"],
            )
        })
        .await?
        .success()?;

    let mut result = HashMap::new();
    for entry in ldap_search_rs {
        let search_entry = ldap3::SearchEntry::construct(entry);
        result.insert(
            search_entry.dn,
            search_entry
                .attrs
                .get("member")
                .unwrap_or(&Vec::<String>::new())
                .clone(),
        );
    }
    Ok(result)
}

pub(crate) async fn get_group_members(
    ldap_conn: &DBLdapConn,
    group_dn: String,
) -> Result<Vec<String>, Error> {
    Ok(get_dn_attrs(ldap_conn, group_dn, "groupOfNames")
        .await?
        .get("member")
        .unwrap_or(&Vec::<String>::new())
        .clone())
}
