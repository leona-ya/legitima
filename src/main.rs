#[macro_use]
extern crate rocket;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

use rocket_sync_db_pools::{database, ldap3};

mod auth;
mod config;
mod controllers;
mod db;
mod error;
mod ldap;
mod routes;

#[database("ldap")]
pub(crate) struct DBLdapConn(ldap3::LdapConn);

#[database("sql")]
pub struct DBSQL(diesel::PgConnection);

#[rocket::main]
async fn main() {
    let _ = routes::build().launch().await;
}
