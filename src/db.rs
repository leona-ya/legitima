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

#[derive(Debug, Clone, Insertable, Queryable, Serialize, Deserialize)]
#[table_name = "group"]
pub(crate) struct DBGroup {
    pub id: i32,
    pub name: String,
    pub ldap_dn: String,
}
