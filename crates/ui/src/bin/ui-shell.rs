#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ui::shell::run().await
}
