# Observer API v7 release candidate

This adds observation metadata without changing BIP300 consensus rules.
`BlockHeaderInfo.work` remains work for that block; `cumulative_work` is the
absolute chain total read from the same LMDB transaction. Consumers must not
interpret the old `work` field as cumulative work.

`GetSeenBmmRequests` requires a ready mempool generation. During initial sync,
recovery or cancellation it returns an unavailable/precondition error, never a
successful empty auction. The session UUID changes on process start; generations
change on attempts/invalidation. ApplySyncActionTimeout joins the existing
bounded recovery policy: five retries, one-second delay, reset after 60 seconds
of operation. Cancellation drops the readiness guard.

`SubscribeMainchainEvents` emits a subscription boundary followed by ordered
committed connect/disconnect transitions, independently of slot subscribers.
Sequence overflow terminates the stream explicitly. It is not a durable replay
log; consumers must record gaps and reconcile headers. `GetChainTip` includes
session and a transactionally persisted revision, which changes even if a reorg
returns to the same hash. Revision metadata survives reopening LMDB and cannot
be emitted for an aborted database transaction.

`GetConfirmedBmmFees` reads the recorded confirmed BMM transaction identities and
requests `getblock HASH 3` from the node. Exact decimal/scientific JSON values
convert to satoshis without floating point. Missing historical prevout fees are
explicitly unavailable, not zero. RPC errors remain errors. This enrichment is
separate from immutable consensus block facts.

Validation: 205 library tests, 15 application tests, including committed-stream
sequence overflow with zero slot listeners, transactional/reopened revisions,
readiness cancellation, exact fees and bounded recovery; workspace compile and
Clippy. Real HOSTKEY acceptance and the 24-hour observation window are pending.
