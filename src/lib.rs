pub mod cli;
pub mod config;
pub mod config_watcher;
pub mod constants;
pub mod helper;
pub mod multi_map;
pub mod protocol;
mod transport;

pub use cli::Cli;
use cli::KeypairType;
pub use config::Config;
pub use constants::UDP_BUFFER_SIZE;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
use client::run_client;

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
use server::run_server;

const DEFAULT_CURVE: KeypairType = KeypairType::X25519;

fn get_str_from_keypair_type(curve: KeypairType) -> &'static str {
    match curve {
        KeypairType::X25519 => "25519",
        KeypairType::X448 => "448",
    }
}

#[cfg(feature = "noise")]
fn genkey(curve: Option<KeypairType>) -> Result<()> {
    let curve = curve.unwrap_or(DEFAULT_CURVE);
    let builder = snowstorm::Builder::new(
        format!(
            "Noise_KK_{}_ChaChaPoly_BLAKE2s",
            get_str_from_keypair_type(curve)
        )
        .parse()?,
    );
    let keypair = builder.generate_keypair()?;

    println!("Private Key:\n{}\n", base64::encode(keypair.private));
    println!("Public Key:\n{}", base64::encode(keypair.public));
    Ok(())
}

#[cfg(not(feature = "noise"))]
fn genkey(curve: Option<KeypairType>) -> Result<()> {
    crate::helper::feature_not_compile("nosie")
}

pub async fn run_instance(
    config: Config,
    args: Cli,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    match determine_run_mode(&config, &args) {
        RunMode::Undetermine => panic!("Cannot determine running as a server or a client"),
        RunMode::Client => {
            #[cfg(not(feature = "client"))]
            crate::helper::feature_not_compile("client");
            #[cfg(feature = "client")]
            run_client(config, shutdown_rx).await
        }
        RunMode::Server => {
            #[cfg(not(feature = "server"))]
            crate::helper::feature_not_compile("server");
            #[cfg(feature = "server")]
            run_server(config, shutdown_rx).await
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum RunMode {
    Server,
    Client,
    Undetermine,
}

fn determine_run_mode(config: &Config, args: &Cli) -> RunMode {
    use RunMode::*;
    if args.client && args.server {
        Undetermine
    } else if args.client {
        Client
    } else if args.server {
        Server
    } else if config.client.is_some() && config.server.is_none() {
        Client
    } else if config.server.is_some() && config.client.is_none() {
        Server
    } else {
        Undetermine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_determine_run_mode() {
    //     use config::*;
    //     use RunMode::*;

    //     struct T {
    //         cfg_s: bool,
    //         cfg_c: bool,
    //         arg_s: bool,
    //         arg_c: bool,
    //         run_mode: RunMode,
    //     }

    //     let tests = [
    //         T {
    //             cfg_s: false,
    //             cfg_c: false,
    //             arg_s: false,
    //             arg_c: false,
    //             run_mode: Undetermine,
    //         },
    //         T {
    //             cfg_s: true,
    //             cfg_c: false,
    //             arg_s: false,
    //             arg_c: false,
    //             run_mode: Server,
    //         },
    //         T {
    //             cfg_s: false,
    //             cfg_c: true,
    //             arg_s: false,
    //             arg_c: false,
    //             run_mode: Client,
    //         },
    //         T {
    //             cfg_s: true,
    //             cfg_c: true,
    //             arg_s: false,
    //             arg_c: false,
    //             run_mode: Undetermine,
    //         },
    //         T {
    //             cfg_s: true,
    //             cfg_c: true,
    //             arg_s: true,
    //             arg_c: false,
    //             run_mode: Server,
    //         },
    //         T {
    //             cfg_s: true,
    //             cfg_c: true,
    //             arg_s: false,
    //             arg_c: true,
    //             run_mode: Client,
    //         },
    //         T {
    //             cfg_s: true,
    //             cfg_c: true,
    //             arg_s: true,
    //             arg_c: true,
    //             run_mode: Undetermine,
    //         },
    //     ];

    //     for t in tests {
    //         let config = Config {
    //             server: match t.cfg_s {
    //                 true => Some(ServerConfig::default()),
    //                 false => None,
    //             },
    //             client: match t.cfg_c {
    //                 true => Some(ClientConfig::default()),
    //                 false => None,
    //             },
    //         };

    //         let args = Cli {
    //             config_path: Some(std::path::PathBuf::new()),
    //             server: t.arg_s,
    //             client: t.arg_c,
    //             ..Default::default()
    //         };

    //         assert_eq!(determine_run_mode(&config, &args), t.run_mode);
    //     }
    // }
}
