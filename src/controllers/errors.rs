use rocket::serde::Serialize;
use rocket::Request;
use rocket_dyn_templates::Template;

// This should not have happened. Please go back to the app you

#[derive(Serialize)]
struct ErrorContext {
    error_title: String,
    error_message: String,
}

#[catch(400)]
pub(crate) fn bad_request() -> Template {
    Template::render(
        "error",
        ErrorContext {
            error_title: "400 - Bad Request".to_owned(),
            error_message: "The request you sent was invalid. When you tried login into a service, please try starting the process again.".to_owned(),
        },
    )
}

#[catch(403)]
pub(crate) fn forbidden() -> Template {
    Template::render(
        "error",
        ErrorContext {
            error_title: "403 - Forbidden".to_owned(),
            error_message: "Oh no! You don't have the required permissions to access this page"
                .to_owned(),
        },
    )
}

#[catch(404)]
pub(crate) fn not_found(req: &Request) -> Template {
    Template::render(
        "error",
        ErrorContext {
            error_title: "404 - Page not found".to_owned(),
            error_message: format!("Oh no! We couldn't find the requested path '{}'", req.uri()),
        },
    )
}

#[catch(500)]
pub(crate) fn internal_server_error() -> Template {
    Template::render(
        "error",
        ErrorContext {
            error_title: "500 - Internal Server Error".to_owned(),
            error_message: "Oh no! An error happened on our site. Please try again later."
                .to_owned(),
        },
    )
}
