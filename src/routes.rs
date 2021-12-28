use crate::config::{AppConfig, HydraConfig};
use crate::DBLdapConn;
use rocket::fs::FileServer;
use rocket::{Build, Rocket};
use rocket_dyn_templates::Template;

pub fn build() -> Rocket<Build> {
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
            "/login",
            routes![
                crate::controllers::login::auth_index,
                crate::controllers::login::index,
                crate::controllers::login::submit
            ],
        )
        .mount(
            "/consent",
            routes![
                crate::controllers::consent::index,
                crate::controllers::consent::approve,
                crate::controllers::consent::reject
            ],
        )
        .mount("/static", FileServer::from(static_root_path))
        .attach(Template::fairing())
        .attach(DBLdapConn::fairing())
        .attach(crate::config::ad_hoc_config::<HydraConfig>("hydra"))
        .attach(crate::config::ad_hoc_config::<AppConfig>("app"))
}
