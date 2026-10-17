#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8104);
    files::run(files::Unit::Manage).await
}
