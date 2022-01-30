use crate::auth::CookieUser;
use rocket::form::{Contextual, Errors, Form};
use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::Redirect;
use rocket::serde::Serialize;
use rocket::State;
use rocket_dyn_templates::Template;

use crate::config::AppConfig;
use crate::error::Error;
use crate::ldap::{change_user_attrs, get_ldap_user};
use crate::DBLdapConn;

#[derive(Serialize)]
struct PersonalDataContext {
    username: String,
    name: String,
    first_name: String,
    last_name: String,
    email: String,
}

#[get("/personal_data", rank = 2)]
pub(crate) async fn get_personal_data(cookies: &CookieJar<'_>) -> Redirect {
    cookies.add(Cookie::new(
        "redirect_url",
        uri!("/selfservice", get_personal_data()).to_string(),
    ));
    Redirect::to(uri!("/auth", crate::controllers::auth::login::login()))
}

#[get("/personal_data")]
pub(crate) async fn auth_get_personal_data(
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    cookie_user: CookieUser,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let ldap_user = get_ldap_user(app_config, ldap_conn, &cookie_user.get_username()[..]).await?;
    Ok(Template::render(
        "selfservice/personal_data",
        PersonalDataContext {
            username: ldap_user.username,
            name: ldap_user.name,
            first_name: ldap_user.first_name,
            last_name: ldap_user.last_name,
            email: ldap_user.email,
        },
    ))
}

#[derive(FromForm)]
pub(crate) struct PersonalDataName<'r> {
    #[field(validate = len(1..))]
    display_name: &'r str,
    #[field(validate = len(1..))]
    first_name: &'r str,
    #[field(validate = len(1..))]
    last_name: &'r str,
}

#[post("/personal_data/name", data = "<form>")]
pub(crate) async fn change_name<'r>(
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    ldap_conn_2: DBLdapConn,
    form: Form<PersonalDataName<'r>>,
    cookie_user: CookieUser,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let form = form.into_inner();
    let changes: Vec<(String, String)> = Vec::from([
        ("displayName".to_owned(), (form.display_name).to_owned()),
        ("cn".to_owned(), (form.first_name).to_owned()),
        ("sn".to_owned(), (form.last_name).to_owned()),
    ]);
    let username = &cookie_user.get_username()[..];
    change_user_attrs(app_config, ldap_conn, username, changes).await?;
    let ldap_user = get_ldap_user(app_config, ldap_conn_2, username).await?;
    Ok(Template::render(
        "selfservice/personal_data",
        PersonalDataContext {
            username: ldap_user.username,
            name: ldap_user.name,
            first_name: ldap_user.first_name,
            last_name: ldap_user.last_name,
            email: ldap_user.email,
        },
    ))
}

#[derive(FromForm)]
pub(crate) struct PersonalDataEmail<'r> {
    #[field(validate = len(1..))]
    email: &'r str,
    #[field()]
    email_validation: &'r str,
}

#[post("/personal_data/email", data = "<form>")]
pub(crate) async fn change_email<'r>(
    app_config: &State<AppConfig>,
    ldap_conn: DBLdapConn,
    ldap_conn_2: DBLdapConn,
    form: Form<PersonalDataEmail<'r>>,
    cookie_user: CookieUser,
) -> Result<Template, Error> {
    let app_config = app_config.inner();
    let form = form.into_inner();
    if form.email != form.email_validation {
        return Err(Error::Http(Status::BadRequest));
    }
    let changes: Vec<(String, String)> = Vec::from([("mail".to_owned(), (form.email).to_owned())]);
    let username = &cookie_user.get_username()[..];
    change_user_attrs(app_config, ldap_conn, username, changes).await?;
    let ldap_user = get_ldap_user(app_config, ldap_conn_2, username).await?;
    Ok(Template::render(
        "selfservice/personal_data",
        PersonalDataContext {
            username: ldap_user.username,
            name: ldap_user.name,
            first_name: ldap_user.first_name,
            last_name: ldap_user.last_name,
            email: ldap_user.email,
        },
    ))
}
