//! A poor-man adaptative barrier.
//!
//! An adaptative barrier blocks all task `wait`ing  at it,
//! unless all of its non-yet dropped clones have also had their `wait` method
//! called.
//!
//! It is "adaptive" because the number of synchronizing task does not have to
//! be known in advance.
//!
//! More info:
//! <https://users.rust-lang.org/t/a-poor-man-async-adaptive-barrier/68118>
use tokio::sync::broadcast::{channel, error::RecvError, Sender};

// TODO: better implementation.

/// An empty enum (non-inhabitated type aka ⊥)
#[derive(Debug, Clone, Copy)]
enum Empty {}

/// Main struct of the module.
#[derive(Debug, Clone)]
pub(crate) struct Barrier {
    inner: Sender<Empty>,
    /// This is ot implement the no-wait
    /// CLI option, used to investigate the race condition
    /// leading to the use of barriers.
    /// It basically deactivates the barrier all together.
    bypass: bool,
}

impl Barrier {
    /// Enters "waiting" mode.
    ///
    ///  Waiting for all existing clones to
    /// enter waitting mode as well.
    pub(crate) async fn wait(self) {
        if self.bypass {
            return;
        }
        let mut receiver = self.inner.subscribe();
        drop(self.inner);
        match receiver.recv().await {
            Ok(_) => unreachable!(),
            Err(RecvError::Lagged(_)) => unreachable!(),
            Err(RecvError::Closed) => (),
        }
    }

    /// Create a new barrier.
    ///
    /// Clone this barrier to wait for more threads.
    pub(crate) fn new(bypass: bool) -> Self {
        Self {
            inner: channel(1).0,
            bypass
        }
    }
}
