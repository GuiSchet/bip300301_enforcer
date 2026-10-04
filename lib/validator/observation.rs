//! Readiness is evidence about a particular mempool generation, not liveness.
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct MempoolReadiness {
    session: Arc<str>,
    state: Arc<parking_lot::Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    enabled: bool,
    generation: u64,
    ready: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotReady {
    Disabled,
    Synchronizing,
}

impl Default for MempoolReadiness {
    fn default() -> Self {
        Self {
            session: uuid::Uuid::from_u128(rand::random()).to_string().into(),
            state: Arc::default(),
        }
    }
}

impl MempoolReadiness {
    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn begin(&self) -> MempoolAttempt {
        let mut state = self.state.lock();
        state.enabled = true;
        state.ready = false;
        state.generation = state
            .generation
            .checked_add(1)
            .expect("mempool generation exhausted");
        MempoolAttempt {
            readiness: self.clone(),
            generation: state.generation,
        }
    }

    pub fn ready_generation(&self) -> Result<u64, NotReady> {
        let state = self.state.lock();
        if !state.enabled {
            Err(NotReady::Disabled)
        } else if !state.ready {
            Err(NotReady::Synchronizing)
        } else {
            Ok(state.generation)
        }
    }

    pub fn invalidate(&self, generation: u64) {
        let mut state = self.state.lock();
        if state.generation == generation {
            state.ready = false;
            // Prevent a task failing immediately after spawn from being marked ready.
            state.generation = state
                .generation
                .checked_add(1)
                .expect("mempool generation exhausted");
        }
    }
}

pub struct MempoolAttempt {
    readiness: MempoolReadiness,
    pub generation: u64,
}

impl MempoolAttempt {
    pub fn mark_ready(&self) {
        let mut state = self.readiness.state.lock();
        if state.generation == self.generation {
            state.ready = true;
        }
    }
}

impl Drop for MempoolAttempt {
    fn drop(&mut self) {
        self.readiness.invalidate(self.generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_or_cancelled_attempt_cannot_serve_an_empty_success() {
        let readiness = MempoolReadiness::default();
        assert_eq!(readiness.ready_generation(), Err(NotReady::Disabled));
        let first = readiness.begin();
        assert_eq!(readiness.ready_generation(), Err(NotReady::Synchronizing));
        readiness.invalidate(first.generation);
        first.mark_ready();
        assert_eq!(readiness.ready_generation(), Err(NotReady::Synchronizing));
        let next = readiness.begin();
        next.mark_ready();
        drop(first);
        assert_eq!(readiness.ready_generation(), Ok(next.generation));
        drop(next);
        assert_eq!(readiness.ready_generation(), Err(NotReady::Synchronizing));
    }
}

/// A single ordered publication point for all committed validator transitions.
/// This fan-out does not depend on any sidechain being active or subscribed.
#[derive(Clone, Debug)]
pub struct ChainOccurrence {
    pub sequence: u64,
    pub event: crate::types::Event,
}

#[derive(Clone)]
pub struct EventSender {
    legacy: async_broadcast::Sender<crate::types::Event>,
    global: async_broadcast::Sender<ChainOccurrence>,
    receiver: async_broadcast::InactiveReceiver<ChainOccurrence>,
    sequence: Arc<parking_lot::Mutex<u64>>,
}

impl EventSender {
    pub fn new(legacy: async_broadcast::Sender<crate::types::Event>) -> Self {
        let (global, mut receiver) = async_broadcast::broadcast(2_000);
        receiver.set_await_active(false);
        receiver.set_overflow(true);
        Self {
            legacy,
            global,
            receiver: receiver.deactivate(),
            sequence: Arc::default(),
        }
    }

    pub fn subscribe(&self) -> (u64, async_broadcast::Receiver<ChainOccurrence>) {
        let sequence = self.sequence.lock();
        (*sequence, self.receiver.activate_cloned())
    }

    #[expect(clippy::result_large_err)] // Preserve the legacy broadcast error API.
    pub fn try_broadcast(
        &self,
        event: crate::types::Event,
    ) -> Result<Option<crate::types::Event>, async_broadcast::TrySendError<crate::types::Event>>
    {
        let mut sequence = self.sequence.lock();
        *sequence = sequence
            .checked_add(1)
            .expect("chain observation sequence exhausted");
        let _result = self.global.try_broadcast(ChainOccurrence {
            sequence: *sequence,
            event: event.clone(),
        });
        let result = self.legacy.try_broadcast(event);
        // Both queues must observe the same order before another publisher runs.
        drop(sequence);
        result
    }
}

/// Tests can retain their local legacy receiver while production fans out both streams.
pub trait CommittedEventSender: Send + Sync {
    fn publish(&self, event: crate::types::Event);
}
impl CommittedEventSender for EventSender {
    fn publish(&self, event: crate::types::Event) {
        let _result = self.try_broadcast(event);
    }
}
impl CommittedEventSender for async_broadcast::Sender<crate::types::Event> {
    fn publish(&self, event: crate::types::Event) {
        let _result = self.try_broadcast(event);
    }
}

#[cfg(test)]
mod stream_tests {
    use bitcoin::hashes::Hash;

    use super::*;

    #[test]
    fn global_stream_needs_no_slot_listener_and_reports_overflow() {
        let (legacy, receiver) = async_broadcast::broadcast(1);
        drop(receiver);
        let sender = EventSender::new(legacy);
        let (boundary, mut stream) = sender.subscribe();
        assert_eq!(boundary, 0);
        let event = crate::types::Event::DisconnectBlock {
            block_hash: bitcoin::BlockHash::all_zeros(),
        };
        // A closed legacy stream must not prevent global publication.
        assert!(sender.try_broadcast(event.clone()).is_err());
        assert_eq!(stream.try_recv().unwrap().sequence, 1);
        for _ in 0..2_001 {
            let _result = sender.try_broadcast(event.clone());
        }
        assert!(matches!(
            stream.try_recv(),
            Err(async_broadcast::TryRecvError::Overflowed(1))
        ));
        assert_eq!(stream.try_recv().unwrap().sequence, 3);
        assert_eq!(sender.subscribe().0, 2_002);
    }

    #[test]
    fn chain_revision_is_transactional_and_survives_restart() {
        let dir = temp_dir::TempDir::new().unwrap();
        {
            let dbs =
                crate::validator::dbs::Dbs::new(dir.path(), bitcoin::Network::Regtest).unwrap();
            let mut tx = dbs.write_txn().unwrap();
            dbs.advance_observation_revision(&mut tx).unwrap();
            drop(tx); // Uncommitted changes must never be reported.
            let mut tx = dbs.write_txn().unwrap();
            assert_eq!(dbs.observation_revision.try_get(&tx, &()).unwrap(), None);
            dbs.advance_observation_revision(&mut tx).unwrap();
            dbs.advance_observation_revision(&mut tx).unwrap(); // A -> B -> A still advances.
            tx.commit().unwrap();
        }
        let dbs = crate::validator::dbs::Dbs::new(dir.path(), bitcoin::Network::Regtest).unwrap();
        let tx = dbs.read_txn().unwrap();
        assert_eq!(dbs.observation_revision.try_get(&tx, &()).unwrap(), Some(2));
    }
}
