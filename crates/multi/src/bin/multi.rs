#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8110);
    multi::run().await
}
