use ory_hydra_client::apis::Error as HydraError;
use rocket::http::Status;
use rocket::response::Responder;
use rocket::Request;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub(crate) enum Error {
    #[error("HTTP status {0}")]
    Http(Status),
    #[error("{0}")]
    Ldap(#[from] ldap3::LdapError),
    #[error("Hydra error, http status {status}")]
    Hydra { status: Status },
}

impl<T> From<HydraError<T>> for Error {
    fn from(err: HydraError<T>) -> Self {
        match err {
            HydraError::ResponseError(err) => {
                if err.status.is_server_error() {
                    Error::Hydra {
                        status: Status::ServiceUnavailable,
                    }
                } else {
                    Error::Hydra {
                        status: Status::BadRequest,
                    }
                }
            }
            _ => Error::Hydra {
                status: Status::InternalServerError,
            },
        }
    }
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        match self {
            Error::Http(s) => s.respond_to(req),
            Error::Ldap(_) => Err(Status::InternalServerError),
            Error::Hydra { status } => Err(status),
        }
    }
}
