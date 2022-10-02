use rocket::{fairing, Build, Rocket};
use rocket_db_pools::Database;
use serde::{Deserialize, Serialize};
use sqlx::pool::PoolConnection;
use sqlx::types::Json;
use sqlx::Postgres;
use totp_rs::Algorithm;
use webauthn_rs::proto::Credential;
use webauthn_rs::{AuthenticationState, RegistrationState};

type Result<T, E = sqlx::Error> = std::result::Result<T, E>;

#[derive(Database)]
#[database("db")]
pub(crate) struct DB(sqlx::PgPool);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DBOAuthClient {
    pub client_id: String,
    pub login_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DBGroup {
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
    pub name: String,
    pub ldap_dn: String,
}

impl DBGroup {
    pub async fn list_all(connection: &mut PoolConnection<Postgres>) -> Result<Vec<DBGroup>> {
        let groups = sqlx::query_as!(DBGroup, r#"SELECT id as "id?", name, ldap_dn FROM "group""#)
            .fetch_all(connection)
            .await?;

        Ok(groups)
    }
    pub async fn find_by_id(id: i32, connection: &mut PoolConnection<Postgres>) -> Result<DBGroup> {
        let groups = sqlx::query_as!(
            DBGroup,
            r#"SELECT id as "id?", name, ldap_dn FROM "group" WHERE id = $1"#,
            id
        )
        .fetch_one(connection)
        .await?;

        Ok(groups)
    }
    pub async fn find_ldap_dn_by_id(
        id: i32,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<String> {
        let group_ldap_dn = sqlx::query!("SELECT ldap_dn FROM \"group\" WHERE id = $1", id)
            .fetch_one(connection)
            .await?
            .ldap_dn;

        Ok(group_ldap_dn)
    }
    pub async fn create_one(
        group: DBGroup,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<i32> {
        let rec = sqlx::query!(
            r#"INSERT INTO "group" (name, ldap_dn) VALUES ($1, $2) RETURNING id"#,
            group.name,
            group.ldap_dn
        )
        .fetch_one(connection)
        .await?;

        Ok(rec.id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DBTotpCredential {
    pub algorithm: Algorithm,
    pub secret: String,
}

pub(crate) trait DBUserCredentialData {}
impl DBUserCredentialData for AuthenticationState {}
impl DBUserCredentialData for RegistrationState {}
impl DBUserCredentialData for Credential {}
impl DBUserCredentialData for DBTotpCredential {}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub(crate) struct DBUserCredential<D: DBUserCredentialData> {
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    pub username: String,
    pub label: Option<String>,
    pub credential_type: DBUserCredentialTypes,
    pub credential_data: Json<D>,
    pub temporary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_credential_types")]
#[sqlx(rename_all = "snake_case")]
pub(crate) enum DBUserCredentialTypes {
    WebauthnAuthentication,
    WebauthnRegistration,
    WebauthnCredential,
    TotpCredential,
}

impl DBUserCredential<AuthenticationState> {
    pub async fn find_webauthn_authentication_by_id_and_username(
        id: uuid::Uuid,
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<DBUserCredential<AuthenticationState>> {
        let webauthn_authentications = sqlx::query_as!(
            DBUserCredential,
            r#"SELECT id as "id?", username, label, credential_type as "credential_type: DBUserCredentialTypes", credential_data as "credential_data!: Json<AuthenticationState>", temporary FROM user_credential WHERE id = $1 AND username = $2 AND credential_type = $3"#,
            id,
            username,
            DBUserCredentialTypes::WebauthnAuthentication as _
        )
            .fetch_one(connection)
            .await?;

        Ok(webauthn_authentications)
    }
}

impl DBUserCredential<RegistrationState> {
    pub async fn find_webauthn_registration_by_id_and_username(
        id: uuid::Uuid,
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<DBUserCredential<RegistrationState>> {
        let webauthn_registrations = sqlx::query_as!(
            DBUserCredential,
            r#"SELECT id as "id?", username, label, credential_type as "credential_type: DBUserCredentialTypes", credential_data as "credential_data!: Json<RegistrationState>", temporary FROM user_credential WHERE id = $1 AND username = $2 AND credential_type = $3"#,
            id,
            username,
            DBUserCredentialTypes::WebauthnRegistration as _
        )
            .fetch_one(connection)
            .await?;

        Ok(webauthn_registrations)
    }
}

impl DBUserCredential<Credential> {
    pub async fn find_webauthn_credentials_by_username(
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<Vec<DBUserCredential<Credential>>> {
        let webauthn_credentials = sqlx::query_as!(
            DBUserCredential,
            r#"SELECT id as "id?", username, label, credential_type as "credential_type: DBUserCredentialTypes", credential_data as "credential_data!: Json<Credential>", temporary FROM user_credential WHERE username = $1 AND credential_type = $2"#,
            username,
            DBUserCredentialTypes::WebauthnCredential as _
        )
            .fetch_all(connection)
            .await?;

        Ok(webauthn_credentials)
    }

    // pub async fn update_counter(
    //     id: &CredentialID,
    //     counter: u32,
    //     connection: &mut PoolConnection<Postgres>,
    // ) -> Result<bool, Error> {
    //     let rows_affected = sqlx::query!(
    //         r#"UPDATE user_credential
    //         SET credential_data['counter'] = $1
    //         WHERE credential_data->>'cred_id' :: int[] = $2 :: int[];"#,
    //         serde_json::to_value(counter)?,
    //         id
    //     )
    //     .execute(connection)
    //     .await?
    //     .rows_affected();
    //
    //     Ok(rows_affected > 0)
    // }
}

impl DBUserCredential<DBTotpCredential> {
    pub async fn find_totp_credentials_by_username(
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<Vec<DBUserCredential<DBTotpCredential>>> {
        let totp_credentials = sqlx::query_as!(
            DBUserCredential,
            r#"SELECT id as "id?", username, label, credential_type as "credential_type: DBUserCredentialTypes", credential_data as "credential_data!: Json<DBTotpCredential>", temporary FROM user_credential WHERE username = $1 AND credential_type = $2"#,
            username,
            DBUserCredentialTypes::TotpCredential as _
        )
            .fetch_all(connection)
            .await?;

        Ok(totp_credentials)
    }
    pub async fn find_totp_credentials_by_id_and_username(
        id: uuid::Uuid,
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<DBUserCredential<DBTotpCredential>> {
        let totp_credential = sqlx::query_as!(
            DBUserCredential,
            r#"SELECT id as "id?", username, label, credential_type as "credential_type: DBUserCredentialTypes", credential_data as "credential_data!: Json<DBTotpCredential>", temporary FROM user_credential WHERE id = $1 AND username = $2 AND credential_type = $3"#,
            id,
            username,
            DBUserCredentialTypes::TotpCredential as _
        )
            .fetch_one(connection)
            .await?;

        Ok(totp_credential)
    }
}

impl<D: DBUserCredentialData + Serialize + Sync> DBUserCredential<D> {
    pub async fn create_one(
        user_credential: DBUserCredential<D>,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<uuid::Uuid> {
        let rec = sqlx::query!(
            "INSERT INTO user_credential (username, label, credential_type, credential_data, temporary) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            user_credential.username,
            user_credential.label,
            user_credential.credential_type as _,
            user_credential.credential_data as _,
            user_credential.temporary
        )
        .fetch_one(connection)
        .await?;

        Ok(rec.id)
    }
    pub async fn update_type_data(
        id: uuid::Uuid,
        credential_type: DBUserCredentialTypes,
        credential_data: Json<D>,
        temporary: bool,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<bool> {
        let rows_affected = sqlx::query!(
            "UPDATE user_credential SET credential_type = $1, credential_data = $2, temporary = $3 WHERE id = $4",
            credential_type as _,
            credential_data as _,
            temporary,
            id
        )
        .execute(connection)
        .await?
        .rows_affected();

        Ok(rows_affected > 0)
    }
    pub async fn delete_credential(
        id: uuid::Uuid,
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<bool> {
        let rows_affected = sqlx::query!(
            "DELETE FROM user_credential WHERE id = $1 AND username = $2",
            id,
            username
        )
        .execute(connection)
        .await?
        .rows_affected();

        Ok(rows_affected == 1)
    }
    pub async fn update_temporary(
        id: uuid::Uuid,
        new_state: bool,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<bool> {
        let rows_affected = sqlx::query!(
            "UPDATE user_credential SET temporary = $1 WHERE id = $2",
            new_state,
            id
        )
        .execute(connection)
        .await?
        .rows_affected();

        Ok(rows_affected > 0)
    }
    pub async fn find_permanent_credentials_by_username(
        username: &str,
        connection: &mut PoolConnection<Postgres>,
    ) -> Result<Vec<DBUserCredentialTypes>> {
        let credentials = sqlx::query!(
            r#"SELECT DISTINCT credential_type as "credential_type: DBUserCredentialTypes" FROM user_credential WHERE username = $1 AND temporary = false"#,
            username,
        )
        .fetch_all(connection)
        .await?;

        Ok(credentials
            .into_iter()
            .map(|cred| cred.credential_type)
            .collect())
    }
}

pub(crate) async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    match DB::fetch(&rocket) {
        Some(db) => match sqlx::migrate!().run(&**db).await {
            Ok(_) => Ok(rocket),
            Err(e) => {
                error!("Failed to initialize SQLx database: {}", e);
                Err(rocket)
            }
        },
        None => Err(rocket),
    }
}
