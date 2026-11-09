# Put a policy decision before one host callback

The [copied host example](../examples/host_dispatch.py) connects the existing
PermitMesh `authorize()` function to an actual, harmless Python callback. The
core remains a policy decision point with no runtime dependencies. This example
is not a production dispatcher, sandbox, authentication service or new core API.

A trusted application owns the contract, current subject/channel/repository,
claim and fence, approval snapshot, budget counters, clock, fixed tool name and
handler registration. Agent input supplies only immutable argument JSON and the
operation nonce. The host must authenticate those trusted inputs before creating
or updating this object; a caller-selected identity or approval is insufficient.

## Run the example

From a source checkout with PermitMesh installed, run:

```sh
python examples/host_dispatch.py
```

The fixed fixture has one approved `test` operation and nonce. Its handler only
appends the supplied dictionary to an in-memory list. The first attempt returns
`RETURNED`, the duplicate is `DENIED` with `NONCE_CONSUMED`, and the list has one
entry. Nothing runs a command, reads/writes a target file, contacts a provider or
publishes content. The explicit 2030 clock replays synthetic validity fixtures;
production context requires a trusted current clock.

Copy the example from a reviewed source checkout or source distribution into a
consumer with a separately installed PermitMesh wheel. It is absent from earlier
source archives. Do not assume a registry package or released tag contains it.
Preserve the wheel SHA-256 and example/source revision when evaluating it.

## The host-owned sequence

1. Bound the immutable JSON argument string to 16,384 characters and 32 nesting
   levels before parsing. Reject duplicate keys, nonfinite numbers, non-object
   roots, collections over 256 items and trees over 4,096 values.
2. Construct and digest the fixed `test` operation with that detached parsed
   argument dictionary. Under one host-owned lock, read current host context and
   build its request around the same operation.
3. Pass the current trusted clock and the host's reserved-nonce set to the
   existing evaluator. A deny result never enters the handler.
4. Reserve an allowed nonce before callback entry while still holding the lock.
   Pass that same parsed argument dictionary to the registered handler. There is
   no second caller lookup or mutable caller dictionary after evaluation.
5. Keep the reservation if an ordinary handler exception makes its effect
   unknown. Return `UNKNOWN` without exception text or automatic retry. Do not
   equate unknown with denial or with a failed effect.

`replace_context()` is a trusted-host method serialized against dispatch. A
changed claim, fence, approval or clock is evaluated at the next admission.
It is not a public context-update or login endpoint. Direct same-instance
callback re-entry returns `HOST_REENTRY`; context replacement during the callback
is rejected. The lock is held until the synchronous callback returns: callbacks
must not start another thread and wait for it to call this dispatcher. Blocking
or nonreturning handlers can block the host indefinitely. There is no timeout,
cancellation, resource isolation or subprocess runner.

## Interpret results narrowly

| Result | What was observed |
| --- | --- |
| `DENIED` | This wrapper did not enter its handler for this attempt. Codes may come from PermitMesh or the example's separate `HOST_*` vocabulary. |
| `RETURNED` | The registered callback returned normally. This does not prove its intended effect succeeded, persisted or occurred exactly once. |
| `UNKNOWN` | The callback raised an ordinary exception after entry; its effect is unresolved and the local nonce stays reserved. |

No callback output, argument payload, host exception text or contract is included
in the result. Digests and reason codes can still reveal sensitive metadata and
require the consuming application's disclosure policy. These Python result
objects are example control flow, not a receipt format or authentication proof.
Process interruption can prevent any result; a surviving local reservation is
not durable state.

Argument binding covers parsed values, not the original JSON whitespace or key
order. Integers retain their precision; non-integer JSON numbers become standard
library `Decimal` values so binary-float rounding cannot change the approved
number. Numeric tokens over 1,024 characters are rejected. A consuming callback
must preserve those parsed values when mapping to its own typed tool arguments.

## Boundaries a real integration still owns

- The local lock and replay set cover only one live object. Constructing another
  object or restarting the process loses that replay history. There is no
  distributed or durable exactly-once guarantee, reservation recovery, signed
  permit verification or authenticated approval storage.
- A contract/claim store outside this object can change concurrently. A protected
  resource must enforce its own current fencing/claim and transaction semantics;
  this Python lock cannot make an external side effect atomic with authorization.
- File, command and cost counters are trusted host snapshots. The fixed fixture
  has one permitted attempt. The example does not add cumulative accounting or
  estimate cost; a real host must supply honest up-to-date counters and reserve
  its budgets transactionally with dispatch.
- Python callers can bypass the object or invoke the original handler directly.
  Keep untrusted agent execution outside that trusted host boundary. A wrapper
  in an unrestricted agent process is not enforcement against that process.
- The callback must translate the checked tool and arguments faithfully. The
  example controls callback admission and the argument snapshot at entry, not
  what arbitrary trusted callback code does afterward.

The existing [BoundaryLab incubator](../incubator/boundarylab/README.md) observes
sandbox behavior and has its own authorization and live-adapter gates. This
example adds no sandbox probes and does not replace that harness. Artifact
authentication, such as the separate Ledger decision example, remains distinct
from callback admission or proof of execution.

## Reproduce the admission checks

The ordinary test suite includes handler-spy assertions for exact arguments,
denial, changed arguments, current approval/claim/fence/clock, concurrent
duplicates, same-thread re-entry and ambiguous callback effects. Run:

```sh
python -m pytest tests/test_host_dispatch.py
```

These are synthetic application-boundary checks. An independently controlled
runtime must reproduce its own integration before claiming adoption or actual
enforcement at a protected resource.
