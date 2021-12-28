use ory_hydra_client::apis::configuration::Configuration;
use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;

#[derive(Deserialize)]
pub struct HydraConfig {
    admin_endpoint_url: String,
    pub consent_remember_me: bool,
    pub consent_remember_me_for: i64,
}

impl HydraConfig {
    pub(crate) fn into_hydra_configuration(&self) -> Configuration {
        Configuration {
            base_path: self.admin_endpoint_url.clone(),
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub ldap_user_base_dn: String,
}

pub(crate) fn ad_hoc_config<'de, T>(sub_figment: &'static str) -> AdHoc
where
    T: serde::Deserialize<'de> + Send + Sync + 'static,
{
    AdHoc::try_on_ignite(std::any::type_name::<T>(), |rocket| async {
        let app_config = match rocket.figment().focus(sub_figment).extract::<T>() {
            Ok(config) => config,
            Err(e) => {
                rocket::config::pretty_print_error(e);
                return Err(rocket);
            }
        };

        Ok(rocket.manage(app_config))
    })
}
