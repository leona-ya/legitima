use rocket::fairing::AdHoc;
use rocket::fs::FileServer;
use rocket::response::Redirect;
use rocket::{Build, Rocket};
use rocket_db_pools::Database;
use rocket_dyn_templates::Template;

use crate::config::{AppConfig, HydraConfig, WebauthnStaticConfig};
use crate::db::DB;
use crate::sessions::SessionStorage;
use crate::{db, DBLdapConn};

#[get("/")]
fn base_redirect() -> Redirect {
    Redirect::to("/selfservice/personal_data")
}

pub(crate) fn build() -> Rocket<Build> {
    let static_root_path = match option_env!("LEGITIMA_STATIC_ROOT_PATH") {
        Some(env) => format!("{}/static/", env),
        None => "static/".to_owned(),
    };
    rocket::build()
        .register(
            "/",
            catchers![
                crate::controllers::errors::bad_request,
                crate::controllers::errors::forbidden,
                crate::controllers::errors::not_found,
                crate::controllers::errors::internal_server_error
            ],
        )
        .mount("/", routes![base_redirect])
        .mount(
            "/auth",
            routes![
                crate::controllers::auth::login::auth_login,
                crate::controllers::auth::login::login,
                crate::controllers::auth::login::submit,
                crate::controllers::auth::login::two_factor,
                crate::controllers::auth::login::totp_2fa,
                crate::controllers::auth::login::webauthn_2fa_challenge_login,
                crate::controllers::auth::login::webauthn_2fa_login
            ],
        )
        .mount(
            "/oidc",
            routes![
                crate::controllers::oidc::login::auth_index,
                crate::controllers::oidc::login::index,
                crate::controllers::oidc::consent::index,
                crate::controllers::oidc::consent::approve,
                crate::controllers::oidc::consent::reject
            ],
        )
        .mount(
            "/selfservice",
            routes![
                crate::controllers::selfservice::personal_data::get_personal_data,
                crate::controllers::selfservice::personal_data::auth_get_personal_data,
                crate::controllers::selfservice::personal_data::change_name,
                crate::controllers::selfservice::personal_data::change_email,
                crate::controllers::selfservice::security::get_security,
                crate::controllers::selfservice::security::auth_get_security,
                crate::controllers::selfservice::security::auth_credential_delete,
                crate::controllers::selfservice::security::auth_webauthn_challenge_register,
                crate::controllers::selfservice::security::auth_webauthn_register,
                crate::controllers::selfservice::security::auth_totp_setup_step1,
                crate::controllers::selfservice::security::auth_totp_setup_step2,
                crate::controllers::selfservice::security::auth_totp_setup_step3,
            ],
        )
        .mount(
            "/admin",
            routes![
                crate::controllers::admin::groups::list_groups,
                crate::controllers::admin::groups::auth_list_groups,
                crate::controllers::admin::groups::auth_edit_group,
                crate::controllers::admin::groups::auth_edit_group_memberform,
                crate::controllers::admin::groups::auth_add_ldap_legitima,
                crate::controllers::admin::groups::auth_add_ldap_legitima_form,
                crate::controllers::admin::groups::auth_add_legitima,
                crate::controllers::admin::groups::auth_add_legitima_form,
            ],
        )
        .mount("/static", FileServer::from(static_root_path))
        .attach(Template::fairing())
        .attach(DBLdapConn::fairing())
        .attach(DB::init())
        .attach(SessionStorage::init())
        .attach(AdHoc::try_on_ignite("SQLx Migrations", db::run_migrations))
        .attach(crate::config::ad_hoc_config::<HydraConfig>("hydra"))
        .attach(crate::config::ad_hoc_config::<AppConfig>("app"))
        .attach(crate::config::ad_hoc_config::<WebauthnStaticConfig>(
            "webauthn",
        ))
}
