//! Share overlapping reads, without retaining a permission snapshot afterwards.
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

type Pending<T> = watch::Receiver<Option<Arc<T>>>;

pub(super) struct Inflight<T> {
    pending: Arc<Mutex<BTreeMap<String, Pending<T>>>>,
}

impl<T: Send + Sync + 'static> Inflight<T> {
    pub(super) fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(super) async fn read(
        &self,
        key: String,
        fetch: impl Future<Output = T> + Send + 'static,
    ) -> Arc<T> {
        let mut receiver = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(receiver) = pending.get(&key) {
                receiver.clone()
            } else {
                let (sender, receiver) = watch::channel(None);
                pending.insert(key.clone(), receiver.clone());
                let pending = self.pending.clone();
                // A caller navigating away must not cancel the shared read for
                // the remaining callers. Completed data is never kept as cache.
                tokio::spawn(async move {
                    let value = Arc::new(fetch.await);
                    pending
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .remove(&key);
                    sender.send_replace(Some(value));
                });
                receiver
            }
        };
        loop {
            if let Some(value) = receiver.borrow_and_update().clone() {
                return value;
            }
            receiver
                .changed()
                .await
                .expect("Discord snapshot producer stopped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn overlapping_reads_share_work_but_next_read_is_fresh() {
        let inflight = Arc::new(Inflight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let inflight = inflight.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                inflight
                    .read("guild-and-credential".into(), async move {
                        let value = calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        value
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(*task.await.unwrap(), 0);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let calls_next = calls.clone();
        assert_eq!(
            *inflight
                .read("guild-and-credential".into(), async move {
                    calls_next.fetch_add(1, Ordering::SeqCst)
                })
                .await,
            1
        );
        assert!(inflight.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn distinct_guild_or_credential_keys_do_not_share_results() {
        let inflight = Inflight::new();
        let (a, b) = tokio::join!(
            inflight.read("guild-a-token-a".into(), async { 1 }),
            inflight.read("guild-b-token-a".into(), async { 2 })
        );
        assert_eq!((*a, *b), (1, 2));
        assert_eq!(
            *inflight.read("guild-a-token-b".into(), async { 3 }).await,
            3
        );
    }

    #[tokio::test]
    async fn cancelled_caller_does_not_cancel_other_waiters() {
        let inflight = Arc::new(Inflight::new());
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let leader = {
            let inflight = inflight.clone();
            let started = started.clone();
            let release = release.clone();
            tokio::spawn(async move {
                inflight
                    .read("shared".into(), async move {
                        started.notify_one();
                        release.notified().await;
                        42
                    })
                    .await
            })
        };
        started.notified().await;
        let follower = tokio::spawn(async move {
            inflight
                .read("shared".into(), async { panic!("duplicate read") })
                .await
        });
        tokio::task::yield_now().await;
        leader.abort();
        release.notify_one();
        assert_eq!(*follower.await.unwrap(), 42);
    }
}
