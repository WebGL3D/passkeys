use std::env;
use std::sync::LazyLock;
use url::Url;

/// The `ORIGIN` environment variable.
/// This is used to determine which host (with scheme) the passkeys belong to.
pub static ORIGIN: LazyLock<Url> = LazyLock::new(|| {
    let origin = env::var("ORIGIN").expect("ORIGIN is not set.");
    Url::parse(&origin).expect("ORIGIN is not a valid URL")
});

/// The hostname, parsed from the `ORIGIN` - port not included.
pub static HOST_NAME: LazyLock<String> =
    LazyLock::new(|| String::from(ORIGIN.host_str().expect("ORIGIN does not have valid host")));
