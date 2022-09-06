use ldap3::Mod;
use rocket::form::validate::Contains;
use rocket::form::{Contextual, Form};
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket::serde::Serialize;
use rocket::{Either, State};
use rocket_db_pools::Connection;
use rocket_dyn_templates::Template;
use std::collections::{HashMap, HashSet};

use crate::config::AppConfig;
use crate::db::{DBGroup, DB};
use crate::error::Error;
use crate::ldap::{add_dn, change_attrs, get_all_groups, get_all_users, get_group_members};
use crate::sessions::AdminUser;
use crate::DBLdapConn;

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
    _user: AdminUser,
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    mut db: Connection<DB>,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let groups = DBGroup::list_all(&mut *db).await?;
    let ldap_groups = get_all_groups(app_config, &ldap_conn).await?;

    Ok(Template::render(
        "admin/groups",
        GroupsContext {
            groups: groups
                .into_iter()
                .map(|db_group| ContextGroup {
                    id: db_group.id.unwrap(),
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
    _user: AdminUser,
    group_id: i32,
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    mut db: Connection<DB>,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let db_group = DBGroup::find_by_id(group_id, &mut *db).await?;
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
pub(crate) async fn auth_edit_group_memberform(
    ldap_conn: DBLdapConn,
    mut db: Connection<DB>,
    group_id: i32,
    form: Form<GroupDataMembers>,
    _user: AdminUser,
) -> Result<Redirect, Error> {
    let form = form.into_inner();
    let changes = Vec::from([Mod::Replace(
        "member".to_owned(),
        HashSet::from_iter(form.members),
    )]);
    let db_group_ldap_dn = DBGroup::find_ldap_dn_by_id(group_id, &mut *db).await?;
    change_attrs(&ldap_conn, db_group_ldap_dn, changes).await?;
    Ok(Redirect::to(uri!("/admin", auth_list_groups)))
}

#[get("/groups/add_ldap_legitima")]
pub(crate) async fn auth_add_ldap_legitima(_user: AdminUser) -> Result<Template, Error> {
    Ok(Template::render(
        "admin/groups_add_ldap_legitima",
        HashMap::<String, String>::new(),
    ))
}

#[derive(FromForm, Debug)]
pub(crate) struct AddLdapLegitimaGroupForm {
    #[field(validate = len(1..))]
    ldap_cn: String,
    #[field(validate = len(1..))]
    legitima_name: String,
}

#[post("/groups/add_ldap_legitima", data = "<form>")]
pub(crate) async fn auth_add_ldap_legitima_form(
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    mut db: Connection<DB>,
    form: Form<Contextual<'_, AddLdapLegitimaGroupForm>>,
    _user: AdminUser,
) -> Result<Either<Redirect, Template>, Error> {
    let app_config = app_config.inner();
    Ok(match form.value {
        Some(ref submission) => {
            let group_dn = format!(
                "cn={},{}",
                submission.ldap_cn, app_config.ldap_groups_base_dn
            );
            add_dn(
                &ldap_conn,
                group_dn.clone(),
                vec![
                    (
                        "objectClass".to_owned(),
                        HashSet::from(["groupOfNames".to_owned(), "top".to_owned()]),
                    ),
                    ("cn".to_owned(), HashSet::from([submission.ldap_cn.clone()])),
                    (
                        "member".to_owned(),
                        HashSet::from([app_config.ldap_root_dn.clone()]),
                    ),
                ],
            )
            .await?;
            DBGroup::create_one(
                DBGroup {
                    id: None,
                    name: submission.legitima_name.clone(),
                    ldap_dn: group_dn,
                },
                &mut *db,
            )
            .await?;
            Either::Left(Redirect::to(uri!("/admin", auth_list_groups)))
        }
        None => Either::Right(Template::render(
            "admin/groups_add_ldap_legitima",
            &form.context,
        )),
    })
}

#[derive(Serialize)]
pub(crate) struct AddLegitimaContext {
    ldap_dn_options: Vec<String>,
}

#[get("/groups/add_legitima")]
pub(crate) async fn auth_add_legitima(
    _user: AdminUser,
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let groups: Vec<String> = get_all_groups(app_config, &ldap_conn)
        .await
        .unwrap_or_default()
        .keys()
        .cloned()
        .collect();

    Ok(Template::render(
        "admin/groups_add_legitima",
        AddLegitimaContext {
            ldap_dn_options: groups,
        },
    ))
}

#[derive(FromForm, Debug)]
pub(crate) struct AddLegitimaGroupForm {
    #[field(validate = len(1..))]
    ldap_dn: String,
    #[field(validate = len(1..))]
    legitima_name: String,
}

#[post("/groups/add_legitima", data = "<form>")]
pub(crate) async fn auth_add_legitima_form(
    mut db: Connection<DB>,
    form: Form<Contextual<'_, AddLegitimaGroupForm>>,
    _user: AdminUser,
) -> Result<Either<Redirect, Template>, Error> {
    Ok(match form.value {
        Some(ref submission) => {
            DBGroup::create_one(
                DBGroup {
                    id: None,
                    name: submission.legitima_name.clone(),
                    ldap_dn: submission.ldap_dn.clone(),
                },
                &mut *db,
            )
            .await?;
            Either::Left(Redirect::to(uri!("/admin", auth_list_groups)))
        }
        None => Either::Right(Template::render("admin/groups_add_legitima", &form.context)),
    })
}
