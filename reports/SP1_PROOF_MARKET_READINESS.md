# SP1 Proof Market Readiness

Snapshot: 2026-08-21. This report covers the hard-cut migration of the Base
history accumulator, recursive accumulator, wash-trading P0 proofs, host
artifact formats, submission scripts, and Solidity verifiers from RISC Zero to
SP1 6.1.0 and the Succinct Prover Network.

## Workload inventory

| Workload | Count | PGU per proof | Aggregate PGU |
| --- | ---: | ---: | ---: |
| Compressed 16,384-header Base epochs | 354 | 538,521,945 | 190,636,768,530 |
| Groth16 recursive accumulator | 1 | 35,140,945 | 35,140,945 |
| Groth16 reciprocal P0 | 24 | 14,838,428 | 356,122,272 |
| Groth16 closed-cycle P0, expected geometry | 2 | 14,838,428 | 29,676,856 |
| Groth16 closed-cycle P0, conservative geometry | 2 | 303,891,006 | 607,782,012 |

Expected geometry totals 191,057,708,603 PGU. Replacing the two expected
closed-cycle proofs with the conservative geometry totals 191,635,813,759 PGU.
The epoch number is from a fresh Base plan spanning blocks 44,469,557 through
50,269,492. The epoch PGU is a real execution of the first full epoch. The
accumulator PGU is a full 354-epoch recursive mock execution. The reciprocal PGU
is the conservative 100-receipt witness. The closed-cycle upper bound is a
modeled conservative geometry and must be replaced by exact execution results
before the final production cost digest is approved.

## Live Succinct market estimate

The read-only mainnet query returned:

| Proof mode | Base fee | Maximum price |
| --- | ---: | ---: |
| Compressed | 0.28885 PROVE | 0.69 PROVE per billion PGU |
| Groth16 | 0.433275 PROVE | 0.69 PROVE per billion PGU |

The estimate uses:

`proof cost = base fee + PGU * price per PGU`

At 0.173353 USD/PROVE, the current expected batch is:

| Workload | PROVE | USD |
| --- | ---: | ---: |
| 354 compressed epochs | 233.792270 | 40.5286 |
| Recursive Groth16 accumulator | 0.457522 | 0.0793 |
| 24 reciprocal Groth16 proofs | 10.644324 | 1.8452 |
| 2 closed-cycle Groth16 proofs, expected | 0.887027 | 0.1538 |
| **Expected total** | **245.781144** | **42.6069** |
| 2 closed-cycle Groth16 proofs, conservative | 1.285920 | 0.2229 |
| **Conservative total** | **246.180036** | **42.6760** |

PROVE/USD and auction prices are volatile. This is a point-in-time estimate, not
a provider quote.

## Enforced spend envelope

Every network request now requires and enforces these approval values:

```text
SP1_NETWORK_MAX_COMPRESSED_BASE_FEE_PROVE_WEI=320000000000000000
SP1_NETWORK_MAX_GROTH16_BASE_FEE_PROVE_WEI=480000000000000000
SP1_NETWORK_MAX_PRICE_PER_PGU_PROVE_WEI=700000000
SP1_NETWORK_REQUIRED_BALANCE_PROVE_WEI=300000000000000000000
```

At the measured PGU values, the approved expected envelope is 259.980396 PROVE
and the conservative envelope is 260.385070 PROVE. Funding 300 PROVE therefore
leaves 39.614930 PROVE, or about 15.2%, above the conservative approved envelope.
The proof hosts reject live fees above the approved mode-specific base fee or
price-per-PGU ceiling. The readiness command additionally rejects an account
below the complete-batch funding requirement. SP1 still simulates each exact
witness locally and puts its measured PGU into the request instead of a loose
manual gas limit.

## Local proving estimate

Measured machine: Apple M3 Max MacBook Pro, 14 CPU cores, 36 GB memory, without
CUDA. A 5,258,360-PGU reciprocal proof ran the SP1 CPU pipeline three times in
1,030.82, 1,062.96, and 1,063.42 seconds using two threads, 262,144-cycle
shards, and reduced-memory configurations. All three runs reached the final
artifact phase but SP1 6.1.0 returned `artifact not found`, including a run with
the default five artifact slots. They establish a reproducible CPU time baseline
but not a completed Groth16 artifact. The 14,838,428-PGU fixture was killed by
the local memory ceiling under two larger-shard configurations.

Scaling the 1,030.82-1,063.42 second baseline linearly by the conservative
191,635,813,759 PGU gives 10,435-10,765 CPU wall-clock hours, or approximately
435-449 days sequentially in the working two-thread low-memory configuration.
This excludes setup duplication, recursive wrapping overhead not reached by the
failed local runs, retries, and I/O, so it is a lower-bound planning estimate.
The full 538,521,945-PGU epoch is not realistically provable on this 36 GB
laptop configuration; a high-memory x86/CUDA workstation or the proof market is
required.

At a sustained 60-100 W system draw and 0.40 EUR/kWh, the direct electricity
range is approximately 250-431 EUR for the conservative batch. Hardware
depreciation, operator time, failures, and the larger-memory machine required
for epoch proofs are excluded. Local CPU proving is therefore slower and has a
higher direct cost than the current 42.68 USD proof-market estimate.

## Submission gate

The next production action is read-only:

```bash
cargo run --release -p loop-host --bin sp1-network-readiness \
  > sp1-network-readiness.json
```

It must print `"ready": true` for the funded production account. Production
proof requests remain blocked until the production `NETWORK_PRIVATE_KEY` is
present and its Succinct account holds at least 300 PROVE. The zero-balance
ephemeral account used for this report submitted no proof.

Proof-market costs exclude Base contract deployment and submission gas. Local
Foundry gas reports measure 542,173 gas to deploy the wash-trading registry and
1,201,819 gas to deploy the checkpoint oracle. Registry overhead, with a mock
verifier, is at most 62,675 gas for a closed-cycle submission and 87,043 gas for
a reciprocal submission. Accumulator submission overhead is at most 125,276 gas
and the tested history-materialization batches range up to 618,562 gas. The
production SP1 gateway verification cost and Base L1 data fee must be added to
those figures. Final fees must therefore be simulated from the exact proof
bundle immediately before deployment because Base execution gas, L1 data fees,
ETH/USD, and proof calldata sizes are all time- and artifact-dependent.
