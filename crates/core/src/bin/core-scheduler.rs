#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8108);
    modlix_core::run_scheduler().await
}
