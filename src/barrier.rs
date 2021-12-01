use tokio::sync::broadcast::{Sender, error::RecvError, channel};

// TODO: better implementation.

#[derive(Debug, Clone, Copy)]
enum Empty {}

#[derive(Debug, Clone)]
pub(crate) struct Barrier {
    inner: Sender<Empty>,
}

impl Barrier {
    pub(crate) async fn wait(self) {
        let mut receiver = self.inner.subscribe();
        drop(self.inner);
        match receiver.recv().await {
            Ok(_) => unreachable!(),
            Err(RecvError::Lagged(_)) => unreachable!(),
            Err(RecvError::Closed) => ()
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            inner: channel(1).0
        }
    }
}