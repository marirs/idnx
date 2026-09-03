pub mod engine;
/// Multi-vantage federation.
///
/// Behind a feature and off by default: it is an unapproved subsystem, and leaving it in
/// the default build meant changes to the core evidence model had to be reflected here to
/// keep compiling -- which is how it came to be edited during unrelated work.
#[cfg(feature = "federation")]
pub mod federation;
pub mod fingerprint;
pub mod net;
pub mod output;
pub mod probes;
pub mod providers;
pub mod text;
pub mod topology;
