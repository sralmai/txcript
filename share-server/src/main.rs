//! `txcript-share-server <config.toml>`

use std::process::ExitCode;
use std::sync::Arc;

use txcript_share_server::{Config, State, Store, router};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("txcript-share-server: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args_os().nth(1) else {
        return Err("usage: txcript-share-server <config.toml>".into());
    };
    let config = Config::load(std::path::Path::new(&path))?;

    let state = Arc::new(State {
        identity: config.identity.build()?,
        policy: config.policy.build()?,
        store: Store::build(&config.store).await,
        limits: config.limits,
    });

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "txcript-share-server listening on {}",
        listener.local_addr()?
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
