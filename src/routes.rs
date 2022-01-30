use crate::config::{AppConfig, HydraConfig};
use crate::DBLdapConn;
use rocket::fs::FileServer;
use rocket::{Build, Rocket};
use rocket_dyn_templates::Template;

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
                crate::controllers::errors::not_found,
                crate::controllers::errors::internal_server_error
            ],
        )
        .mount(
            "/auth",
            routes![
                crate::controllers::auth::login::auth_login,
                crate::controllers::auth::login::login,
                crate::controllers::auth::login::submit
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
            ],
        )
        .mount("/static", FileServer::from(static_root_path))
        .attach(Template::fairing())
        .attach(DBLdapConn::fairing())
        .attach(crate::config::ad_hoc_config::<HydraConfig>("hydra"))
        .attach(crate::config::ad_hoc_config::<AppConfig>("app"))
}
