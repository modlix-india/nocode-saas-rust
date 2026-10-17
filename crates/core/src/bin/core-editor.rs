//! core-editor: the Java core's editing surface (port 8111).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform::app::healthcheck_if_asked(8111);
    modlix_core::editor::run().await
}
