use std::env;
use std::sync::LazyLock;

/// Reads `HELLO` from the environment variables.
pub static HELLO: LazyLock<String> =
    LazyLock::new(|| env::var("HELLO").expect("HELLO is not set."));
