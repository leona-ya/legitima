table! {
    groups (id) {
        id -> Int4,
        name -> Varchar,
        ldap_path -> Varchar,
    }
}

table! {
    groups_permissions (id) {
        id -> Int4,
        client_id -> Varchar,
        group_id -> Int4,
    }
}

table! {
    oauth_clients (client_id) {
        client_id -> Varchar,
        login_allowed -> Bool,
    }
}

joinable!(groups_permissions -> groups (group_id));
joinable!(groups_permissions -> oauth_clients (client_id));

allow_tables_to_appear_in_same_query!(
    groups,
    groups_permissions,
    oauth_clients,
);
