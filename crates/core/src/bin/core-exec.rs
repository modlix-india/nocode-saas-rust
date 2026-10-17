#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8105);
    modlix_core::run_exec().await
}
