# Chain Governor Security Invariants

> [!NOTE]  
> This document is intended to assist developers, auditors, and security researchers assess the security of the Chain Governor
> implementation. It should aid in understanding the security constraints of the system and can act as a checklist
> for evaluating Governor behavior and modifications.

> [!IMPORTANT]  
> Identifying a missing invariant in a Chain Governor implementation is not sufficient for claiming a bug bounty.
> A real issue must be identified in line with the documented policy on ImmuneFi.

## Transfer Value Accounting

### INV-GOV-001: Daily Limit Enforcement for Small Transfers

- **Invariant**: The sum of small transfer values within any 24-hour sliding window must not exceed the configured daily limit for a chain
- **Description**: Small transfers (below the big transaction threshold) are aggregated and compared against the daily limit. When the limit is exceeded, subsequent transfers are enqueued until capacity becomes available
- **Enforcement**: Real-time computation of 24-hour rolling sum with enqueuing logic
- **Error Conditions**: Transfers enqueued when `newTotalValue > dailyLimit`
- **Code Reference**: `processMsgForTime()` in `governor.go:577-589`, `trimAndSumValueForChain()` in `governor.go:1042`

### INV-GOV-002: Big Transfer Delay Requirement

- **Invariant**: All transfers with value >= the big transaction threshold must be delayed for 24 hours before processing
- **Description**: Large transactions are always enqueued regardless of current capacity to provide a detection window for exploits
- **Enforcement**: Value-based classification and mandatory enqueuing with 24-hour release timer
- **Error Conditions**: Big transfers enqueued when `value >= bigTransactionSize`
- **Code Reference**: `processMsgForTime()` in `governor.go:564-576`, `isBigTransfer()` in `governor.go:215-217`

### INV-GOV-003: Transfer Value Calculation Consistency

- **Invariant**: Once a transfer is published, its contribution to the daily limit is fixed at the time of publication
- **Description**: The USD value of a transfer is calculated using the token price at publication time and does not change retroactively
- **Enforcement**: Transfer value is computed once and stored in the database; pending transfer values are recomputed at each interval
- **Error Conditions**: Computational errors in `computeValue()`
- **Code Reference**: `processMsgForTime()` in `governor.go:539-548`, `computeValue()` in `governor.go:949-966`

### INV-GOV-004: No Arithmetic Overflow in Value Calculations

- **Invariant**: All value arithmetic operations must be checked for overflow/underflow
- **Description**: Prevents integer overflow when summing transfer values or adding new transfers
- **Enforcement**: Explicit overflow checking with `CheckedAddUint64()` and `CheckedAddInt64()`
- **Error Conditions**: Return error when overflow/underflow would occur
- **Code Reference**: `processMsgForTime()` in `governor.go:550-560`, `CheckedAddUint64()` in `governor.go:1123-1138`, `CheckedAddInt64()` in `governor.go:1142-1166`

## Message Hashing and Identity

### INV-GOV-005: Message Hash Uniqueness

- **Invariant**: Each unique message must produce a unique hash derived from its VAA signing digest
- **Description**: Message identity is based on VAA signing digest to ensure consistent hashing across guardians
- **Enforcement**: Hash computed from `v.SigningDigest()` using canonical VAA format
- **Error Conditions**: Hash collisions would violate deduplication guarantees
- **Code Reference**: `hashFromMsg()` in `governor.go:1116-1120`

### INV-GOV-006: Hash Computation Consistency

- **Invariant**: The hash of a message must be deterministic and independent of guardian set index
- **Description**: Ensures all guardians compute the same hash for the same message
- **Enforcement**: Guardian set index passed as 0 in VAA creation for hashing
- **Error Conditions**: Non-deterministic hashing would break deduplication across guardians
- **Code Reference**: `hashFromMsg()` in `governor.go:1116-1120`, comment: "We can pass zero in as the guardian set index because it is not part of the digest"

## Transfer Deduplication and Ordering

### INV-GOV-007: No Duplicate Transfer Processing

- **Invariant**: Each unique transfer can only be processed once by the Governor
- **Description**: Prevents double-counting transfers in daily limit calculations by tracking message hashes
- **Enforcement**: Hash-based tracking in `msgsSeen` map with `transferComplete` or `transferEnqueued` state
- **Error Conditions**: Duplicate published transfers allowed but not counted toward limit; duplicate enqueued transfers rejected
- **Code Reference**: `processMsgForTime()` in `governor.go:506-523`, `hashFromMsg()` in `governor.go:1116-1120`

### INV-GOV-008: Transfer State Consistency

- **Invariant**: A transfer must be in exactly one state: not seen, enqueued, or completed
- **Description**: State transitions are unidirectional: not seen → enqueued → completed (or not seen → completed for immediate publishing)
- **Enforcement**: State tracked via `msgsSeen` map and presence in `chainEntry.pending` or `chainEntry.transfers`
- **Error Conditions**: Hash tracked in `msgsSeen` with boolean indicating completion state
- **Code Reference**: `processMsgForTime()` in `governor.go:608-609`, `checkPendingForTime()` in `governor.go:908-924`

### INV-GOV-009: Pending Transfer Release Timing

- **Invariant**: Enqueued transfers can only be released when capacity is available OR 24 hours have elapsed
- **Description**: Transfers are released early if they fit within capacity; otherwise they are released after maximum enqueue time
- **Enforcement**: Time-based release checking in periodic pending scan combined with capacity checking
- **Error Conditions**: Early release when `prevTotalValue + value <= dailyLimit`; forced release when `now.After(releaseTime)`
- **Code Reference**: `checkPendingForTime()` in `governor.go:814-855`

## Token Price Management

### INV-GOV-010: Price Floor Protection

- **Invariant**: Token prices must never fall below the configured floor price
- **Description**: Uses the maximum of the static configured price and the dynamic CoinGecko price to prevent undervaluation due to price oracle manipulation
- **Enforcement**: `updatePrice()` selects max(coinGeckoPrice, cfgPrice)
- **Error Conditions**: Price automatically reverted to configured value if CoinGecko fails or returns lower value
- **Code Reference**: `updatePrice()` in `governor_prices.go:309-315`, `queryCoinGecko()` in `governor_prices.go:140-251`

### INV-GOV-011: Price Update Atomicity

- **Invariant**: Price updates must be atomic across all tokens sharing a CoinGecko ID
- **Description**: Multiple tokens can share the same price feed; all must update consistently
- **Enforcement**: Batch update of all tokens in `tokensByCoinGeckoId` array
- **Error Conditions**: CoinGecko query failure results in all affected tokens reverting to configured prices
- **Code Reference**: `queryCoinGecko()` in `governor_prices.go:188-226`, `revertAllPrices()` in `governor_prices.go:290-306`

### INV-GOV-012: Price Update Failure Safety

- **Invariant**: The Governor must remain operational when price updates fail
- **Description**: CoinGecko failures should not halt Governor operation; prices revert to safe configured values
- **Enforcement**: Error handling in price query with fallback to configured prices
- **Error Conditions**: Logged errors but no propagation; operation continues with configured prices
- **Code Reference**: `queryCoinGecko()` in `governor_prices.go:171-174`, `revertAllPrices()` in `governor_prices.go:290-306`

## Flow Canceling

### INV-GOV-013: Flow Cancel Non-Negativity

- **Invariant**: The net Governor usage for a chain (outbound minus flow cancel) must never be negative
- **Description**: When incoming flow-canceling transfers exceed outgoing transfers, the available capacity is the full daily limit, not a negative value
- **Enforcement**: Explicit check in `trimAndSumValueForChain()` returns 0 when sum is negative
- **Error Conditions**: Sum capped at 0 when negative; sum capped at dailyLimit when exceeding limit
- **Code Reference**: `trimAndSumValueForChain()` in `governor.go:1042-1062`, `availableNotionalValue()` in `governor_monitoring.go:427-442`

### INV-GOV-014: Flow Cancel Asset Restriction

- **Invariant**: Only explicitly configured tokens can flow cancel
- **Description**: Flow canceling is opt-in; only tokens in the Flow Cancel Token List have `flowCancels=true`
- **Enforcement**: Token registration during config initialization sets `flowCancels` flag
- **Error Conditions**: Non-flow-cancel tokens ignored in `tryAddFlowCancelTransfer()`
- **Code Reference**: `initConfig()` in `governor.go:377-397`, `tryAddFlowCancelTransfer()` in `governor.go:972-1027`

### INV-GOV-015: Flow Cancel Corridor Restriction

- **Invariant**: Flow canceling can only occur between explicitly configured chain pairs (corridors)
- **Description**: A flow cancel corridor is a bidirectional pair of chains; transfers only flow cancel when both source and destination are in a configured corridor
- **Enforcement**: Corridor validation in `corridorCanFlowCancel()` before applying flow cancel effect
- **Error Conditions**: Flow cancel rejected if corridor not configured
- **Code Reference**: `corridorCanFlowCancel()` in `governor.go:676-689`, `tryAddFlowCancelTransfer()` in `governor.go:979-984`

### INV-GOV-016: Flow Cancel Value Inversion

- **Invariant**: Flow cancel transfers must have negative value relative to the destination chain
- **Description**: Incoming transfers reduce the destination chain's Governor usage by applying a negative-valued transfer
- **Enforcement**: Explicit sign flip when adding flow cancel transfer; validation in `addFlowCancelTransfer()`
- **Error Conditions**: Error returned if flow cancel transfer value is not negative
- **Code Reference**: `addFlowCancelTransfer()` in `governor.go:166-192`, `inverse()` in `governor.go:210-213`

### INV-GOV-017: Flow Cancel Target Chain Matching

- **Invariant**: Flow cancel transfers must target the chain they are intended to affect
- **Description**: A flow cancel transfer's `TargetChain` must match the `emitterChainId` of the chain entry it's added to
- **Enforcement**: Explicit validation in `addFlowCancelTransfer()`
- **Error Conditions**: Error returned if `targetChain != ce.emitterChainId`
- **Code Reference**: `addFlowCancelTransfer()` in `governor.go:186-188`

### INV-GOV-018: Flow Cancel Disabled by Default

- **Invariant**: Flow canceling functionality must be explicitly enabled
- **Description**: Flow canceling is opt-in via configuration flag to allow operators to disable if malicious activity detected
- **Enforcement**: `flowCancelEnabled` flag checked before applying flow cancel logic
- **Error Conditions**: Flow cancel operations skipped when `!gov.flowCancelEnabled`
- **Code Reference**: `corridorCanFlowCancel()` in `governor.go:678-681`, `processMsgForTime()` in `governor.go:660-670`

## Database and State Persistence

### INV-GOV-019: Database Write Atomicity for Published Transfers

- **Invariant**: A published transfer must be successfully written to the database before being added to the in-memory state
- **Description**: Ensures database and memory state remain consistent; prevents lost transfers on restart
- **Enforcement**: Database write must succeed before modifying in-memory `chainEntry.transfers`
- **Error Conditions**: Return error and halt processing if database write fails
- **Code Reference**: `processMsgForTime()` in `governor.go:640-648`

### INV-GOV-020: Database Write Atomicity for Enqueued Transfers

- **Invariant**: An enqueued transfer must be successfully written to the database before being added to the pending queue
- **Description**: Ensures pending transfers persist across guardian restarts
- **Enforcement**: Database write must succeed before adding to `chainEntry.pending`
- **Error Conditions**: Return error and halt processing if database write fails
- **Code Reference**: `processMsgForTime()` in `governor.go:593-602`

### INV-GOV-021: Transfer Cleanup After Release

- **Invariant**: Pending transfers must be removed from the database when released or dropped
- **Description**: Prevents stale entries in the database and duplicate processing on restart
- **Enforcement**: Database deletion must succeed before removing from in-memory pending queue
- **Error Conditions**: Return error and halt processing if database deletion fails
- **Code Reference**: `checkPendingForTime()` in `governor.go:930-933`, `ReleasePendingVAA()` in `governor_monitoring.go:205-207`

### INV-GOV-022: Expired Transfer Pruning

- **Invariant**: Transfers older than 24 hours must be removed from the database and in-memory state
- **Description**: Keeps the sliding window accurate and prevents unbounded memory/storage growth
- **Enforcement**: Time-based filtering in `trimAndSumValue()` with database deletion
- **Error Conditions**: Return error if database deletion fails
- **Code Reference**: `trimAndSumValue()` in `governor.go:1096-1107`, `loadFromDBAlreadyLocked()` in `governor_db.go:56-59`

### INV-GOV-023: State Recovery on Restart

- **Invariant**: All transfers and pending messages must be reloaded from the database on guardian restart
- **Description**: Ensures the Governor resumes with accurate state after downtime
- **Enforcement**: Database query and validation during `loadFromDB()`
- **Error Conditions**: Invalid transfers/pending messages are logged and skipped
- **Code Reference**: `loadFromDBAlreadyLocked()` in `governor_db.go:22-64`, `reloadTransfer()` in `governor_db.go:143-233`

### INV-GOV-024: Flow Cancel Reconstruction on Restart

- **Invariant**: Flow cancel transfers must be reconstructed from regular transfers on guardian restart
- **Description**: Flow cancel transfers are not stored in the database; they are derived from completed transfers
- **Enforcement**: `tryAddFlowCancelTransfer()` called during transfer reload if flow cancel enabled
- **Error Conditions**: Failure to add flow cancel transfer is logged but does not halt restart
- **Code Reference**: `reloadTransfer()` in `governor_db.go:226-231`

## Message Validation and Filtering

### INV-GOV-025: Governed Chain Restriction

- **Invariant**: Only transfers from explicitly configured chains are governed
- **Description**: Prevents processing of unexpected chain messages; non-configured chains pass through immediately
- **Enforcement**: Chain existence check in `parseMsgAlreadyLocked()`
- **Error Conditions**: Returns `msgIsGoverned=false` for non-configured chains
- **Code Reference**: `parseMsgAlreadyLocked()` in `governor.go:703-713`

### INV-GOV-026: Governed Emitter Restriction

- **Invariant**: Only transfers from the configured token bridge emitter address are governed
- **Description**: Ensures only official token bridge contracts are monitored
- **Enforcement**: Emitter address matching in `parseMsgAlreadyLocked()`
- **Error Conditions**: Returns `msgIsGoverned=false` for non-configured emitters
- **Code Reference**: `parseMsgAlreadyLocked()` in `governor.go:715-722`

### INV-GOV-027: Transfer Type Restriction

- **Invariant**: Only token transfer messages (types 1 and 3) are governed
- **Description**: Non-transfer messages pass through immediately without Governor checks
- **Enforcement**: Transfer type validation using `vaa.IsTransfer()`
- **Error Conditions**: Returns `msgIsGoverned=false` for non-transfer payloads
- **Code Reference**: `parseMsgAlreadyLocked()` in `governor.go:724-728`

### INV-GOV-028: Governed Token Restriction

- **Invariant**: Only explicitly configured tokens are governed
- **Description**: Prevents thinly-traded tokens with unreliable prices from affecting Governor; opt-in token list
- **Enforcement**: Token existence check in `parseMsgAlreadyLocked()`
- **Error Conditions**: Returns `msgIsGoverned=false` for non-configured tokens
- **Code Reference**: `parseMsgAlreadyLocked()` in `governor.go:736-742`

### INV-GOV-029: Payload Decoding Validation

- **Invariant**: Transfer payload must be decodable and valid
- **Description**: Malformed payloads are rejected to prevent processing errors
- **Enforcement**: Payload decoding with error handling in `parseMsgAlreadyLocked()`
- **Error Conditions**: Returns error for invalid payloads
- **Code Reference**: `parseMsgAlreadyLocked()` in `governor.go:730-734`

## Release and Administrative Operations

### INV-GOV-030: Manual Release Bypass

- **Invariant**: Manually released transfers must not count toward the daily limit
- **Description**: Guardian admin override allows release without consuming capacity, enabling emergency responses
- **Enforcement**: Transfers released via `ReleasePendingVAA()` are not added to `chainEntry.transfers`
- **Error Conditions**: Manual release proceeds regardless of capacity
- **Code Reference**: `ReleasePendingVAA()` in `governor_monitoring.go:184-217`, comment at `governor.go:119`

### INV-GOV-031: Expired Release Bypass

- **Invariant**: Transfers released after 24-hour timeout must not count toward the daily limit
- **Description**: Prevents indefinite queueing; after maximum hold time, transfers are released regardless of capacity
- **Enforcement**: Time-based release with `countsTowardsTransfers=false` when `now.After(releaseTime)`
- **Error Conditions**: Expired transfers skip daily limit accounting
- **Code Reference**: `checkPendingForTime()` in `governor.go:827-834`, comment at `governor.go:123`

### INV-GOV-032: Release Timer Extension Authorization

- **Invariant**: Only authorized administrators can extend the release timer for pending transfers
- **Description**: Provides additional investigation time for suspicious transfers
- **Enforcement**: Admin command validation (implementation-specific)
- **Error Conditions**: Timer can be extended up to 30 days
- **Code Reference**: `ResetReleaseTimer()` in `governor_monitoring.go:220-252`, whitepaper section "Operational Considerations"

### INV-GOV-033: Pending Transfer Drop Authorization

- **Invariant**: Only authorized administrators can remove transfers from the pending queue
- **Description**: Enables censorship of fraudulent transfers by individual guardians
- **Enforcement**: Admin command validation (implementation-specific)
- **Error Conditions**: Dropped transfers are removed from database and memory
- **Code Reference**: `DropPendingVAA()` in `governor_monitoring.go:155-182`

### INV-GOV-034: Pending Transfer Release Order

- **Invariant**: The Governor must attempt to release pending transfers in optimal order
- **Description**: Smaller pending transfers can be released before larger ones if they fit within available capacity
- **Enforcement**: Iterative checking of all pending transfers to find those that fit
- **Error Conditions**: Continue checking all pending transfers even if earlier ones cannot fit
- **Code Reference**: `checkPendingForTime()` in `governor.go:799-843`

## Configuration and Initialization

### INV-GOV-035: Non-Empty Configuration Requirement

- **Invariant**: The Governor must have at least one configured chain and one configured token
- **Description**: Prevents invalid Governor instances that cannot process any transfers
- **Enforcement**: Configuration validation during initialization
- **Error Conditions**: Return error if no chains or tokens configured
- **Code Reference**: `initConfig()` in `governor.go:399-401`, `initConfig()` in `governor.go:444-446`

### INV-GOV-036: Chain Configuration Validity

- **Invariant**: All configured chains must have a valid token bridge emitter address
- **Description**: Ensures the Governor can correctly identify token bridge messages
- **Enforcement**: Emitter address lookup during initialization
- **Error Conditions**: Return error if emitter address not found or invalid
- **Code Reference**: `initConfig()` in `governor.go:410-422`

### INV-GOV-037: Token Decimal Normalization

- **Invariant**: Token decimals must be capped at 8 for Governor calculations
- **Description**: Transfer payloads use at most 8 decimal places; prevents precision issues
- **Enforcement**: Decimal capping during token configuration
- **Error Conditions**: Decimals silently capped at 8
- **Code Reference**: `initConfig()` in `governor.go:326-330`

### INV-GOV-038: Deterministic Chain Iteration

- **Invariant**: Chain entries must be processed in a deterministic order
- **Description**: Ensures consistent behavior across guardians and executions
- **Enforcement**: Sorted `chainIds` slice used for iteration instead of map
- **Error Conditions**: N/A - enforced by sorted slice
- **Code Reference**: `initConfig()` in `governor.go:448-462`, `checkPendingForTime()` in `governor.go:778-779`

### INV-GOV-039: Flow Cancel Configuration Consistency

- **Invariant**: Flow cancel tokens must also be in the main token list
- **Description**: Prevents flow canceling for non-governed tokens
- **Enforcement**: Only sets `flowCancels=true` if token exists in `gov.tokens`
- **Error Conditions**: Tokens in flow cancel list but not main list are logged and skipped
- **Code Reference**: `initConfig()` in `governor.go:386-396`

## Capacity and Threshold Management

### INV-GOV-040: Big Transaction Threshold Consistency

- **Invariant**: Big transaction size must be less than or equal to the daily limit
- **Description**: Ensures big transactions can eventually be released after 24 hours without violating capacity
- **Enforcement**: Implementation assumption - no explicit check in code
- **Error Conditions**: Misconfiguration could cause permanent queueing
- **Code Reference**: Configuration in `mainnet_chains.go`, logic in `governor.go:215-217`

### INV-GOV-041: Available Capacity Calculation Accuracy

- **Invariant**: Available capacity must equal daily limit minus current 24-hour usage (or zero if usage exceeds limit)
- **Description**: Accurate capacity reporting for monitoring and decision-making
- **Enforcement**: Calculation in `availableNotionalValue()` using 24-hour rolling sum
- **Error Conditions**: Returns 0 when usage >= limit; returns dailyLimit when usage is negative
- **Code Reference**: `availableNotionalValue()` in `governor_monitoring.go:427-442`

### INV-GOV-042: Sliding Window Accuracy

- **Invariant**: Only transfers within the last 24 hours must contribute to the current capacity calculation
- **Description**: Implements true sliding window (not calendar day) for rate limiting
- **Enforcement**: Time-based filtering with `startTime = now - 24 hours`
- **Error Conditions**: Expired transfers pruned and not counted
- **Code Reference**: `checkPendingForTime()` in `governor.go:769`, `trimAndSumValue()` in `governor.go:1071-1110`

## Monitoring and Observability

### INV-GOV-043: Gossip Configuration Publication

- **Invariant**: Governor configuration must be published to the gossip network periodically
- **Description**: Enables monitoring and comparison of guardian configurations
- **Enforcement**: Configuration published every 5 minutes via gossip
- **Error Conditions**: Publication failures are logged but do not halt Governor
- **Code Reference**: `publishConfig()` in `governor_monitoring.go:575-633`, `CollectMetrics()` in `governor_monitoring.go:561-564`

### INV-GOV-044: Gossip Status Publication

- **Invariant**: Governor status must be published to the gossip network periodically
- **Description**: Provides real-time visibility into pending transfers and capacity
- **Enforcement**: Status published every minute via gossip
- **Error Conditions**: Publication failures are logged but do not halt Governor
- **Code Reference**: `publishStatus()` in `governor_monitoring.go:635-718`, `CollectMetrics()` in `governor_monitoring.go:566-569`

### INV-GOV-045: Metrics Consistency

- **Invariant**: Prometheus metrics must accurately reflect Governor state
- **Description**: Enables alerting and monitoring of Governor health
- **Enforcement**: Metrics updated during periodic collection
- **Error Conditions**: Overflow errors in sum calculation result in 0 reported capacity
- **Code Reference**: `CollectMetrics()` in `governor_monitoring.go:497-570`

### INV-GOV-046: Limited Gossip Message Size

- **Invariant**: Gossip messages must have bounded size to prevent network issues
- **Description**: Only the first 20 enqueued VAAs are included in status messages
- **Enforcement**: Limit on number of pending transfers included in gossip
- **Error Conditions**: Additional pending transfers are counted but not detailed
- **Code Reference**: `publishStatus()` in `governor_monitoring.go:657-665`, comment at `governor_monitoring.go:73`

## Error Handling and Resilience

### INV-GOV-047: Safe Error Propagation

- **Invariant**: Critical errors must halt processing; non-critical errors must be logged and recovered
- **Description**: Database errors and overflow errors are critical; price update failures are not
- **Enforcement**: Error return from `processMsgForTime()` and `checkPendingForTime()` for critical errors
- **Error Conditions**: Processor restart on critical errors; continued operation on non-critical errors
- **Code Reference**: `ProcessMsg()` in `governor.go:468-476`, `queryCoinGecko()` in `governor_prices.go:119-133`

### INV-GOV-048: Database Connection Resilience

- **Invariant**: Database connection failures during release processing must halt the Guardian
- **Description**: Cannot tolerate loss of transfer state during release operations
- **Enforcement**: Database errors returned from `checkPendingForTime()` causing processor restart
- **Error Conditions**: Processor dies on database write/delete failures
- **Code Reference**: `checkPendingForTime()` in `governor.go:900-904`, `checkPendingForTime()` in `governor.go:930-933`

### INV-GOV-049: Value Overflow Halt

- **Invariant**: Integer overflow in transfer value calculations must halt processing
- **Description**: Cannot tolerate incorrect capacity calculations due to overflow
- **Enforcement**: Checked arithmetic with error returns
- **Error Conditions**: Error returned and processing halted on overflow
- **Code Reference**: `CheckedAddUint64()` in `governor.go:1123-1138`, `processMsgForTime()` in `governor.go:550-560`

### INV-GOV-050: Malformed Transfer Handling

- **Invariant**: Malformed pending transfers discovered during release must be dropped and cleaned up
- **Description**: Prevents indefinite stalling of Governor due to corrupted pending data
- **Enforcement**: Payload decode errors during release result in pending transfer removal
- **Error Conditions**: Hash removed from `msgsSeen` and transfer deleted from database
- **Code Reference**: `checkPendingForTime()` in `governor.go:857-864`

## Reobservation and Duplicate Handling

### INV-GOV-051: Reobservation Allowance for Published Transfers

- **Invariant**: Published transfers can be reobserved and republished without affecting the daily limit
- **Description**: Allows VAA reconstruction via reobservation without double-counting
- **Enforcement**: Duplicate check allows republishing but skips accounting
- **Error Conditions**: Duplicate published transfers return `true` (publishable) but not counted
- **Code Reference**: `processMsgForTime()` in `governor.go:516-523`

### INV-GOV-052: Reobservation Rejection for Enqueued Transfers

- **Invariant**: Enqueued transfers cannot be reobserved and must wait for release
- **Description**: Prevents bypassing the queue by reobserving
- **Enforcement**: Duplicate check returns `false` (not publishable) for enqueued transfers
- **Error Conditions**: Duplicate enqueued transfers are rejected
- **Code Reference**: `processMsgForTime()` in `governor.go:507-515`

### INV-GOV-053: Flow Cancel Reobservation Exclusion

- **Invariant**: Reobserved messages must not trigger flow canceling effects
- **Description**: Prevents stale reobservations from affecting current capacity calculations
- **Enforcement**: Flow cancel only applied to first observation (implementation-specific check needed)
- **Error Conditions**: Only new observations trigger flow cancel
- **Code Reference**: Whitepaper section "Flow Canceling" criteria, `processMsgForTime()` in `governor.go:660-670`
