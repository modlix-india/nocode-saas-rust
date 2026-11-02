#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8113);
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = security::admin::run_if_asked(&args).await {
        std::process::exit(code);
    }
    security::admin::run().await
}
