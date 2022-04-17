use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use ldap3::Mod;
use rocket::form::validate::Contains;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::Redirect;
use rocket::serde::Serialize;
use rocket::State;
use rocket_dyn_templates::Template;
use std::collections::HashSet;

use crate::auth::CookieUser;
use crate::config::AppConfig;
use crate::db::DBGroup;
use crate::error::Error;
use crate::ldap::{change_attrs, get_all_groups, get_all_users, get_group_members};
use crate::{db, DBLdapConn, DBSQL};

#[derive(Serialize)]
struct GroupsContext {
    groups: Vec<ContextGroup>,
}

#[derive(Serialize)]
struct ContextGroup {
    id: i32,
    name: String,
    ldap_dn: String,
    members: Option<Vec<String>>,
    user_member_mapping: Option<Vec<(String, bool)>>,
}

#[get("/groups", rank = 2)]
pub(crate) async fn list_groups(cookies: &CookieJar<'_>) -> Redirect {
    cookies.add(Cookie::new(
        "redirect_url",
        uri!("/admin", auth_list_groups()).to_string(),
    ));
    Redirect::to(uri!("/auth", crate::controllers::auth::login::login()))
}

#[get("/groups")]
pub(crate) async fn auth_list_groups(
    user: CookieUser,
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    db_sql: DBSQL,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    if !user.is_admin(app_config, &ldap_conn).await? {
        return Err(Error::Http(Status::Forbidden));
    }
    let groups: Vec<DBGroup> = db_sql
        .run(move |conn| db::group::table.load::<DBGroup>(conn))
        .await?;
    let ldap_groups = get_all_groups(app_config, &ldap_conn).await?;

    Ok(Template::render(
        "admin/groups",
        GroupsContext {
            groups: groups
                .into_iter()
                .map(|db_group| ContextGroup {
                    id: db_group.id,
                    name: db_group.name,
                    members: Some(
                        ldap_groups
                            .get(&db_group.ldap_dn)
                            .unwrap_or(&Vec::new())
                            .clone(),
                    ),
                    ldap_dn: db_group.ldap_dn,
                    user_member_mapping: None,
                })
                .collect(),
        },
    ))
}

#[get("/groups/<group_id>")]
pub(crate) async fn auth_edit_group(
    user: CookieUser,
    group_id: i32,
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    db_sql: DBSQL,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    if !user.is_admin(app_config, &ldap_conn).await? {
        return Err(Error::Http(Status::Forbidden));
    }
    let db_group: DBGroup = db_sql
        .run(move |conn| {
            db::group::table
                .filter(db::group::id.eq(group_id))
                .first::<DBGroup>(conn)
        })
        .await?;
    let ldap_group_members = get_group_members(&ldap_conn, db_group.ldap_dn.clone()).await?;
    let ldap_all_users = get_all_users(app_config, &ldap_conn).await?;
    let ldap_user_mapping: Vec<(String, bool)> = ldap_all_users
        .iter()
        .map(|user| (user.clone(), ldap_group_members.contains(user)))
        .collect();

    Ok(Template::render(
        "admin/groups_edit",
        ContextGroup {
            id: group_id,
            name: db_group.name,
            ldap_dn: db_group.ldap_dn,
            user_member_mapping: Some(ldap_user_mapping),
            members: None,
        },
    ))
}

#[derive(FromForm)]
pub(crate) struct GroupDataMembers {
    #[field(validate = len(1..))]
    members: Vec<String>,
}

#[post("/groups/<group_id>/members", data = "<form>")]
pub(crate) async fn auth_edit_group_memberform<'r>(
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    db_sql: DBSQL,
    group_id: i32,
    form: Form<GroupDataMembers>,
    user: CookieUser,
) -> Result<Redirect, Error> {
    let app_config = app_config.inner();
    if !user.is_admin(app_config, &ldap_conn).await? {
        return Err(Error::Http(Status::Forbidden));
    }
    let form = form.into_inner();
    let changes = Vec::from([Mod::Replace(
        "member".to_owned(),
        HashSet::from_iter(form.members),
    )]);
    let db_group_ldap_dn: String = db_sql
        .run(move |conn| {
            db::group::table
                .filter(db::group::id.eq(group_id))
                .select(db::group::ldap_dn)
                .first(conn)
        })
        .await?;
    change_attrs(&ldap_conn, db_group_ldap_dn, changes).await?;
    Ok(Redirect::to(uri!("/admin", auth_list_groups)))
}
