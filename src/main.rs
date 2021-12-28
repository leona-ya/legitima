#[macro_use]
extern crate rocket;

use rocket_sync_db_pools::{database, ldap3};

mod auth;
mod config;
mod controllers;
mod error;
mod routes;

#[database("ldap")]
pub struct DBLdapConn(ldap3::LdapConn);

#[rocket::main]
async fn main() {
    let _ = routes::build().launch().await;
}
