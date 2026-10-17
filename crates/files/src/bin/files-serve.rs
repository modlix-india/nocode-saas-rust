#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8103);
    files::run(files::Unit::Serve).await
}
