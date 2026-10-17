#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ui::editor::run().await
}
