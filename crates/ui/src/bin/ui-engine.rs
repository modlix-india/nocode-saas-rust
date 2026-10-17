#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ui::run().await
}
