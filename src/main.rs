#[macro_use]
extern crate rocket;

use rocket_sync_db_pools::{database, ldap3};

mod config;
mod controllers;
mod db;
mod error;
mod ldap;
mod routes;
mod sessions;

#[database("ldap")]
pub(crate) struct DBLdapConn(ldap3::LdapConn);

#[rocket::main]
async fn main() {
    let _ = routes::build().launch().await;
}
