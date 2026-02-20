use std::future::Future;
use std::io;

use tokio_util::sync::CancellationToken;

mod connection;
mod protocol;

pub use connection::handle_connection;
pub(crate) use protocol::ProtocolError;

async fn cancellable_io<T, F>(shutdown: &CancellationToken, operation: F) -> Result<T, io::Error>
where
    F: Future<Output = Result<T, io::Error>>,
{
    tokio::select! {
        _ = shutdown.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown")),
        result = operation => result,
    }
}
