use crate::DBSQL;
use rocket::{Build, Rocket};
use rocket_sync_db_pools::diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

table! {
    group (id) {
        id -> Int4,
        name -> Varchar,
        ldap_dn -> Varchar,
    }
}

table! {
    group_permission (id) {
        id -> Int4,
        client_id -> Varchar,
        group_id -> Int4,
    }
}

table! {
    oauth_client (client_id) {
        client_id -> Varchar,
        login_allowed -> Bool,
    }
}

joinable!(group_permission -> group (group_id));
joinable!(group_permission -> oauth_client (client_id));

allow_tables_to_appear_in_same_query!(group, group_permission, oauth_client,);

#[derive(Debug, Clone, Insertable, Queryable)]
#[table_name = "oauth_client"]
pub(crate) struct DBOAuthClient {
    pub client_id: String,
    pub login_allowed: bool,
}

#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub(crate) struct DBGroup {
    pub id: i32,
    pub name: String,
    pub ldap_dn: String,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[table_name = "group"]
pub(crate) struct DBInsertGroup {
    pub name: String,
    pub ldap_dn: String,
}

pub(crate) async fn run_migrations(rocket: Rocket<Build>) -> Rocket<Build> {
    embed_migrations!("migrations");

    let conn = DBSQL::get_one(&rocket).await.expect("database connection");
    conn.run(|c| embedded_migrations::run(c))
        .await
        .expect("diesel migrations");

    rocket
}
