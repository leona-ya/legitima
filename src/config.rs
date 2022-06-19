use ory_hydra_client::apis::configuration::Configuration;
use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use webauthn_rs::WebauthnConfig;

#[derive(Deserialize)]
pub(crate) struct HydraConfig {
    admin_endpoint_url: String,
    pub(crate) consent_remember_me: bool,
    pub(crate) consent_remember_me_for: i64,
}

impl HydraConfig {
    pub(crate) fn as_hydra_configuration(&self) -> Configuration {
        Configuration {
            base_path: self.admin_endpoint_url.clone(),
            ..Default::default()
        }
    }
}

#[derive(Deserialize, Clone)]
pub(crate) struct WebauthnStaticConfig {
    rp_name: String,
    rp_id: String,
    rp_origin: url::Url,
}

impl std::fmt::Debug for WebauthnStaticConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "WebauthnStaticConfig{{ rp_name: {:?}, rp_id: {:?}, rp_origin: {:?} }}",
            self.rp_name, self.rp_id, self.rp_origin
        )
    }
}

impl WebauthnConfig for WebauthnStaticConfig {
    fn get_relying_party_name(&self) -> &str {
        &self.rp_name
    }

    fn get_origin(&self) -> &url::Url {
        &self.rp_origin
    }

    fn get_relying_party_id(&self) -> &str {
        &self.rp_id
    }
}

#[derive(Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) name: String,
    pub(crate) ldap_user_base_dn: String,
    pub(crate) ldap_groups_base_dn: String,
    pub(crate) ldap_admin_group_dn: String,
    pub(crate) ldap_root_dn: String,
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
