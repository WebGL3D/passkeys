use std::env;
use std::sync::LazyLock;
use url::Url;

/// Reads the `JWT__PUBLIC_KEY` from the environment variables.
pub static JWT_PUBLIC_KEY: LazyLock<String> =
    LazyLock::new(|| env::var("JWT__PUBLIC_KEY").expect("JWT__PUBLIC_KEY is not set."));

/// Reads the `JWT__PRIVATE_KEY` from the environment variables.
pub static JWT_PRIVATE_KEY: LazyLock<String> =
    LazyLock::new(|| env::var("JWT__PRIVATE_KEY").expect("JWT__PRIVATE_KEY is not set."));

/// The `ORIGIN` environment variable.
/// This is used to determine which host (with scheme, and port) the passkeys belong to.
static ORIGIN: LazyLock<Url> = LazyLock::new(|| {
    let origin = env::var("ORIGIN").expect("ORIGIN is not set.");
    Url::parse(&origin).expect("ORIGIN is not a valid URL")
});

/// The `iss` assigned to the JWT.
pub static ISSUER: LazyLock<String> =
    LazyLock::new(|| ORIGIN.to_string().trim_end_matches("/").to_string());

/// The hostname, parsed from the `ORIGIN` - port not included.
pub static HOST_NAME: LazyLock<String> =
    LazyLock::new(|| String::from(ORIGIN.host_str().expect("ORIGIN does not have valid host")));
