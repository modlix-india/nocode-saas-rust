#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8761);
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = lighthouse::config::cli::run_if_asked(&args).await {
        std::process::exit(code);
    }
    lighthouse::run().await
}
