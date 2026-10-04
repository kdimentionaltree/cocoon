# Two-CVM WireGuard acceptance

Use this procedure on two dedicated Intel TDX workers before loading a distributed model. It tests the production admission/service path, ordinary application traffic and collective transport. It does not implement distributed SGLang/vLLM rank launch or turn diagnostic JSON into externally verifiable cluster evidence.

The tooling is implemented and locally tested. **The full new image build/boot, kernel namespace harness and actual two-CVM run remain pending.** Record those separately; loopback tests with synthetic evidence cannot satisfy hardware acceptance.

## Build and prepare

Build the guest with the repository's [reproducible image procedure](../../reprodebian/README.txt). Regenerate an old cache whose kernel was already pruned without WireGuard. The build resolves and validates the actual WireGuard/nf_tables module dependencies; it must not be bypassed.

The image installs:

- `/usr/bin/cocoon-wireguard` and its opt-in service/preparation helper;
- `/usr/bin/cocoon-wireguard-acceptance`, a Python standard-library checker and temporary echo tool;
- `/usr/share/cocoon/wireguard-collective.py`, for execution inside the approved inference image with PyTorch.

Prepare rank 0/1 worker policies from the [examples](worker-a.example.json) with one mutually required peer each. Use distinct `/32` addresses in a nonconflicting overlay subnet, exact approved workload/generation, the measured operator public key, and the intended TDX image authorization policy. The standard overlay ports are UDP 51820 and admission TCP 51821. Actual host ports include `instance * 10`; record the launcher output and put those host ports in peer endpoint hints.

Use the [bootstrap procedure](README.md#guest-image-and-launcher-integration-step-5): obtain both public enrollment exports, independently approve the finalized measurements, sign the intended current boot/key allocations on the authority, and atomically deliver the same envelope to both prepared runtime paths. The default 300-second lease requires coordinated renewal during a longer test session. Record the signed grant digest and expiry, not the authority's private key.

Public enrollment is an identity offer, not evidence. Production admission still verifies DCAP, certificate measurements, fresh challenge quotes, and exact signed boot/key/context bindings. The checker does not relax or replace those checks.

### Debug runs without TEE hardware

The same networking and service checks support guests launched with `--no-tee`. Follow the [fake-mode bootstrap instructions](README.md#debug-guests-with---no-tee): the launcher prepares `attestation.type: "fake_tee"`; enroll both current debug guests and sign a new payload with every member's `tee_type: "fake_tee"` and synthetic image hash. Rebuild the guest image to include this implementation. Real-mode grants cannot be reused and real workers reject debug membership.

The acceptance checker automatically validates the fake configuration against the guest's `cocoon_no_tee` boot flag and passes the daemon's `--no-tee` flag internally. Add `--no-tee` to direct `cocoon-wireguard check-gate` commands below. Acceptance, status and collective output records `attestation_type: "fake_tee"`. Keep the same readiness, routing, MTU, failure, lease and cleanup checks. Fake mode demonstrates encrypted networking and service behavior without hardware attestation; record its results separately from the real-TDX ledger.

After bootstrap, stop the engine and worker runner on **both** test workers to free resources while leaving the overlay running. Choose the actual backend unit:

```bash
systemctl stop cocoon-worker-runner.service cocoon-sglang.service
umask 077
mkdir -p /run/cocoon-wireguard-acceptance
```

Use `cocoon-vllm.service` for vLLM. Record guest image/spec/model identifiers, kernel version, CPU/GPU allocation, actual inference image digest, host endpoint mappings, current boot enrollment, and both guest clocks. Keep test outputs in an operator-controlled directory; an old surviving report is not current readiness.

## Live readiness and direct routes

Run on each worker:

```bash
cocoon-wireguard-acceptance inspect --backend sglang --wait 30 \
  > /run/cocoon-wireguard-acceptance/ready.json
cocoon-wireguard check-gate --config /run/spec/wireguard-config.json \
  > /run/cocoon-wireguard-acceptance/gate.json
```

Select `--backend vllm` as appropriate. `inspect` validates the exact static nftables policy using the daemon's read-only `check-gate` command. It checks expiring permissions, a live notification-ready process, status freshness, lease/context, interface type/ownership/MTU, local public key, healthy required peers, exact kernel keys/AllowedIPs, overlay routes and consumer `BindsTo`/`After` dependencies. It does not require the engine to be running yet. Stale status alone never passes.

Compare the `membership_sha256` fields from both reports. They must match the same operator-approved signed grant. Inspect the guest's underlay routes separately if an endpoint is unreachable; endpoint hints cannot authorize a different peer.

Never collect `wg show ... dump`, private key files, `identity.bin`, or signing PEM files for a report. `wg show wg0 public-key`, `allowed-ips`, `latest-handshakes`, and `transfer` are public diagnostic views. The checker reads only the first two.

## Bidirectional application traffic and MTU

On worker B, start the bounded echo server in one terminal:

```bash
cocoon-wireguard-acceptance serve --port 29501 --seconds 120 \
  > /run/cocoon-wireguard-acceptance/server.log
```

Wait for its `listening` event, then on A:

```bash
cocoon-wireguard-acceptance exchange --peer worker-b --port 29501 \
  --count 8 --seconds 30 > /run/cocoon-wireguard-acceptance/a-to-b.json
```

Repeat with the server on A and `--peer worker-a` on B. Both TCP and UDP exchanges must pass in each direction. TCP transfers use 256 KiB random test bodies, exercising segmentation; UDP uses `MTU - 28` bytes with IPv4 fragmentation prohibited. At MTU 1400 the UDP body is 1372 bytes. These are correctness/RTT observations, not sustained-bandwidth or model-performance benchmarks. The server expires after its specified duration and accepts only allocated peer source addresses. No firewall permissions or peer keys are installed by this tool.

Both server and client bind the local overlay address and exact interface. If the overlay disappears, the test fails; it cannot switch its own traffic to an underlay interface. This does **not** substitute for testing ordinary unbound application sockets and the retained fallback guard.

For the underlay checks, generate only synthetic test traffic:

1. Capture the relevant host/vNIC underlay during the successful exchanges. Check that workload traffic goes through encrypted WireGuard UDP and that no ordinary TCP 29501 or cleartext test payload appears on an underlay path. Limit captures to this test; guest overlay captures contain plaintext.
2. Test underlay reachability of the temporary application listener through the actual host network/mapping. It must be unreachable. Confirm the server really is listening on the overlay address and reachable through the overlay first; a refusal from a missing listener proves nothing.
3. After stopping/removing the overlay, test an ordinary **unbound** socket toward the old peer overlay address while capturing the underlay. A timeout/refusal by itself is insufficient: confirm the exact retained output drop and no leaked workload packet. The device-bound exchange helper intentionally is not the fallback-routing test.

Record the capture interface, filter, test interval and observed result. Packet captures and diagnostic snapshots are operational evidence; they are not a new cryptographic attestation format.

## CPU Gloo and GPU NCCL

Use the same exact, approved inference-image digest on both workers. For example, the currently measured SGLang service pins its runtime digest; retrieve the value from that deployment. Resolve and approve an exact digest before testing a vLLM image whose existing template uses `latest`.

Run the following concurrently on both workers, substituting the approved image:

```bash
IMAGE='registry/runtime@sha256:APPROVED_DIGEST'
docker run --rm --network=host --ipc=host --entrypoint=python3 \
  -v /usr/share/cocoon/wireguard-collective.py:/test.py:ro \
  -v /run/spec/wireguard-config.json:/config.json:ro \
  "$IMAGE" /test.py --config /config.json --backend gloo \
  --port 29500 --seconds 90 > /run/cocoon-wireguard-acceptance/gloo.log 2>&1
```

Then repeat concurrently with GPU access and NCCL:

```bash
docker run --rm --network=host --ipc=host --gpus all --entrypoint=python3 \
  -v /usr/share/cocoon/wireguard-collective.py:/test.py:ro \
  -v /run/spec/wireguard-config.json:/config.json:ro \
  "$IMAGE" /test.py --config /config.json --backend nccl \
  --port 29500 --seconds 90 > /run/cocoon-wireguard-acceptance/nccl.log 2>&1
```

The script derives rank and leader overlay address from the two-worker configuration. It fixes Gloo to the interface and NCCL to the exact interface, Socket transport and IPv4, disables InfiniBand and separate NCCL OOB network selection, and emits initialization/network logs. Check both logs for successful results and the expected `NET/Socket` transport/interface. A configured environment alone is not observed transport evidence. [NCCL transport/interface options](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/env.html).

The rank-0 rendezvous listener is also bound to its overlay address/device: the script passes that listener's descriptor to `TCPStore` with `use_libuv=False`. This avoids an all-address rendezvous listener. The inference image must support these PyTorch arguments; an unsupported backend/API fails the test. [PyTorch TCPStore](https://docs.pytorch.org/docs/stable/distributed.html#torch.distributed.TCPStore).

Both ranks all-reduce float tensors at three sizes and verify **every element equals 3**. The parent enforces a hard whole-process deadline covering import, initialization, collectives and shutdown. Keep renewing the same approved lease during these checks. They test one GPU per guest; intra-guest multi-GPU topology and full model parallelism are separate acceptance tests.

## Failure and rejection matrix

Run failures individually on dedicated test workers. Capture readiness, consumer state and traffic **before** intervention, observe automatic withdrawal, then stop both overlays before recovery. Stopping the other overlay manually before observing withdrawal would conceal a failed automatic-stop check.

| Test | Intervention | Required observation |
| --- | --- | --- |
| Normal stop | Stop one `cocoon-wireguard.service` | Required-peer liveness expires; ordinary traffic closes and bound consumers stop on both workers |
| Interface loss | Bring the owned interface down or delete it | Inventory/liveness detects failure; no consumer continues serving; exact fallback guards remain |
| Forced daemon death | Kill the overlay's main process | Kernel permissions cannot be refreshed; watchdog/restart/cleanup and required-peer failure close workload access |
| Stalled daemon | Stop scheduling the main process temporarily with SIGSTOP | Timed sets expire or watchdog cleanup closes access; retained status cannot certify readiness |
| Lease expiry | Withhold renewal until the signed lease expires | Healthy WireGuard cryptographic sessions cannot continue authorizing workloads |
| Invalid live envelope | Atomically replace membership with a deliberately corrupted signature | Immediate fail-closed withdrawal; no partial-file acceptance |
| Substituted member/key | Deliver an authority-signed test grant with a changed intended boot/key | Local identity or fresh peer binding rejects it; no workload-ready state |
| Wrong image/workload/generation | Deliver deliberately mismatched test authorization | Configuration/quote/context verification rejects it; no authorized workload traffic |
| Guest reboot | Reboot one test CVM, retaining its old membership | New boot/key enrollment requires a new grant; old authorization cannot establish readiness |
| Recovery | Re-enroll/approve where required, supply a common current grant, restart overlays and then consumers | Both nodes independently regain readiness; no rank is served during incomplete recovery |

For a forced-death test, use `systemctl kill --kill-whom=main --signal=SIGKILL cocoon-wireguard.service` on the selected test worker. Account for the unit's automatic restarts: record its transitions and consumer state, not just one successful snapshot after recovery. For interface loss use the configured name, never an arbitrary host interface.

The ten-second watchdog can close traffic before the kernel peer timeout. To isolate kernel expiry while an interface remains up, use the namespace harness below, or an approved dedicated test configuration with a peer deadline shorter than the watchdog; record actual timed-set expiry and process/interface state before cleanup. A test where watchdog cleanup wins does not prove independent kernel expiry.

Generate deliberately wrong signed grants on the authority, never copy its private signing key into a guest. Use separate filenames and atomic delivery. After each negative test, restore a current valid common grant; an expired one is not a recovery artifact. Saved state binds boot/context and is never silently regenerated.

Stale-challenge replay, quoted key substitution, wrong-platform/missing evidence and TLS/session reflection already have focused synthetic-evidence tests. Real-hardware protocol-adversary coverage needs an external adversarial participant; this runbook does not expose a production fake-attestation mode or label those synthetic cases as hardware-tested.

After automatic withdrawal has been recorded, quiesce both overlays and validate completed cleanup on each node:

```bash
systemctl stop cocoon-wireguard.service
cocoon-wireguard-acceptance inspect --expect closed --backend sglang --wait 20 \
  > /run/cocoon-wireguard-acceptance/closed.json
```

The closed check requires a stopped overlay, stopped bound consumers, absence of the owned interface and empty workload permission sets, while checking the exact retained static guard. It is not intended to pass during an automatic restart or a deliberately frozen live process.

Restore approved grants/configuration and start both overlays together. Use `systemctl reset-failed` after exhausting restart limits. Once both ready checks and bidirectional exchanges pass, restart bound consumers together. Replaced boot/key/image identities require renewed operator approval. Automatic coherent distributed-engine restart remains future integration work.

## Local checks and evidence ledger

The relevant local commands are:

```bash
CCACHE_DISABLE=1 cmake --build build --target cocoon-wireguard test-wireguard test-wireguard-admission -j4
build/tee/test-wireguard
build/tee/test-wireguard-admission
python3 tee/test/wireguard-cli.py build/tee/cocoon-wireguard
python3 tee/test/wireguard-integration.py
python3 tee/test/wireguard-acceptance.py
```

The final two scripts test installation/integration and acceptance logic; service/policy mutations are substituted. Acceptance socket tests exchange actual loopback TCP/UDP and validate a real address-bound rendezvous listener with PyTorch substituted. No actual collective, hardware quote or kernel WireGuard packet is demonstrated by these local tests.

The focused native suite also passed AddressSanitizer/UndefinedBehaviorSanitizer after rebuilding the changed device/test paths under instrumentation (leak detection disabled). SDK-enabled syntax checks passed for admission, evidence and the updated CLI. These checks do not replace the guest build or real hardware run.

On a separate Linux test machine with the required privileges and kernel support:

```bash
sudo python3 tee/test/wireguard-network.py build/tee/test-wireguard-admission
```

This confines devices and policy to isolated namespaces and uses synthetic attestation. Namespace creation is unavailable in the current workspace, including outside its application sandbox. A full image build was attempted with the project's mkosi 26~devel virtual environment and separate `/tmp` output/cache/workspace paths. It failed at namespace creation (`Operation not permitted`), before package installation or image construction, including outside the application sandbox. Existing guest images were not replaced. Guest boot and live admission also require a TDX host; this workspace has no TDX/KVM devices.

Maintain one ledger per deployment:

| Evidence | Current workspace status | Deployment result to record |
| --- | --- | --- |
| Native enrollment and admission/device/probe/supervisor/gate tests | Passed: 445 and 1,049 assertions | Binary/build identity and output |
| CLI signature checks | Passed: 34 commands, independent OpenSSL verification | Output |
| Guest/launcher install/integration tests | Passed: 13 tests | Output |
| Acceptance tooling tests | Passed: 16 tests, including local TCP/UDP | Output |
| General `test-cocoon` target | Cannot compile: pre-existing obsolete header/API references | Repair/migrate that target separately |
| Complete new mkosi image and TDX boot | Blocked locally by namespace creation; no new image built | Image/spec measurements and boot logs |
| Isolated kernel packet harness | Pending | Output and kernel version |
| Production two-CVM admission and bidirectional traffic | Pending | Both reports, matching grant, traffic outputs and underlay observations |
| Failure/rejection/recovery matrix | Pending on actual workers | Intervention, timed observations, consumer state and recovery |
| Gloo and GPU NCCL collectives | Pending; PyTorch/GPU runtime unavailable locally | Both logs, exact image digest, Socket transport and correct results |
| Distributed SGLang/vLLM serving | Outside the first overlay service; pending | Approved rank launch, cluster serving identity and coherent restart tests |

Complete hardware acceptance only after the intended CVMs pass the applicable live rows. Keep external approval of final images and the limitations of status/public enrollment explicit in the result.
