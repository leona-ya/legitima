use rocket::{fairing, Build, Rocket};
use rocket_db_pools::Database;
use serde::{Deserialize, Serialize};
use sqlx::pool::PoolConnection;
use sqlx::Postgres;

type Result<T, E = sqlx::Error> = std::result::Result<T, E>;

#[derive(Database)]
#[database("db")]
pub(crate) struct DB(sqlx::PgPool);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DBOAuthClient {
    pub client_id: String,
    pub login_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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
