# WireGuard service for confidential workers

The service implementation and step-6 acceptance tooling are available: strict configuration, protected identities, signed membership, fresh mutually attested admission, WireGuard setup, lease/liveness supervision, opt-in guest/launcher integration, and a [two-CVM acceptance procedure](acceptance.md). `run` opens workload traffic only after the required group is admitted and healthy, renews admission, and withdraws access on failure. `setup` remains a diagnostic with workload traffic blocked. The image build installs the daemon, tools, preparation helper and unit; measured worker configuration opts in. Full new image build/boot, real two-CVM acceptance and distributed engine rank launch remain outstanding.

**An enrollment export is not hardware attestation evidence.** Real-mode exports carry `attestation_status: "not_collected"`; explicit fake-mode exports carry `"synthetic"`. The signing helper authorizes the supplied identities; it does not verify their hardware evidence. `verify-membership` verifies the operator signature, allocation, validity, and local identity, not remote TDX quotes. Live peer admission independently checks the configured evidence mode before enabling workload traffic.

## Build and check

```bash
cmake --build build --target cocoon-wireguard test-wireguard test-wireguard-admission -j 4
build/tee/test-wireguard
build/tee/test-wireguard-admission
build/tee/cocoon-wireguard --help
python3 tee/test/wireguard-cli.py build/tee/cocoon-wireguard
python3 tee/test/wireguard-fake-tee.py build/tee/cocoon-wireguard
python3 tee/test/wireguard-integration.py build/tee/cocoon-wireguard
python3 tee/test/wireguard-acceptance.py
```

The executable is a Linux target and uses the existing OpenSSL, JSON, and Cocoon dependencies. The local tests need ordinary loopback UDP and Unix datagram access but require no elevated networking privileges or TDX hardware. If installed, the `ip` helper is also exercised for read-only link inventory. The application network sandbox may block those operations. Real-mode `admit-peer`, `setup`, and `run` require TDX/DCAP and confidential guests; explicit fake mode runs without that SDK or hardware. Actual WireGuard setup still needs Linux WireGuard/nftables support and guest root. `cleanup` performs no admission and works without that SDK.

`check-gate --config FILE` is read-only: it checks the exact static owned firewall and prints its current nftables JSON, including timed-set elements. It does not acquire the live daemon's identity lock, generate keys, flush permissions or claim fresh attestation. Missing or altered gates fail. The [acceptance checker](acceptance.py) combines that inventory with live systemd state, fresh status, exact public keys/routes and temporary device-bound TCP/UDP exchanges; it supports TDX and explicitly booted fake-mode guests and never changes peer or firewall configuration. The image also packages a [Gloo/NCCL smoke test](collective.py) for use in the approved inference container. Follow the [acceptance runbook](acceptance.md) for installation, failure tests, collective logs and the pending hardware evidence ledger.

## Debug guests with `--no-tee`

Launch a WireGuard-enabled worker using the existing `scripts/cocoon-launch --no-tee` flag. The launcher changes `attestation.type` to `fake_tee` in the prepared spec, preserves the source configuration, and retains endpoint forwarding. The guest requires `cocoon_no_tee` to match that explicit policy and propagates `--no-tee` to enrollment, membership verification, the daemon and cleanup. Missing TDX hardware never automatically selects fake mode. `--no-cc` alone keeps real attestation selected.

Use the normal bootstrap procedure with a fresh enrollment from each debug guest. Every member of the signed payload must have `tee_type: "fake_tee"` and its synthetic image hash. Read the existing `<cert_base_name>_image_hash.b64` emitted by `gen-cert --tee fake_tee` and convert it to hex, for example:

```bash
python3 -c 'import base64,sys; print(base64.b64decode(open(sys.argv[1]).read()).hex())' /etc/tee/tee_image_hash.b64
```

Both Intel and AMD fake certificates are supported, including a pair with different CPU vendors. Intel fake measurements are now zero-initialized so the reported image hash is deterministic; AMD fake VCEK generation also initializes its OpenSSL key pointer. The example `signed_membership` policy works in fake mode; a pinned allowlist must contain the synthetic hashes. A real membership cannot be reused. Fake membership uses the distinct signed binary domain `cocoon/wg-membership/fake-tee/v1` followed by NUL; real v1 signatures and identities retain their existing encoding. Mixed real/fake membership and reuse of a real-mode identity directory fail.

For direct daemon use, set `attestation.type` to `fake_tee` in the configuration and pass the standalone flag on every configuration command:

```bash
cocoon-wireguard enroll --config worker-fake.json --no-tee
cocoon-wireguard verify-membership --config worker-fake.json --membership cluster-membership.json --no-tee
cocoon-wireguard run --config worker-fake.json --membership cluster-membership.json --no-tee
```

The signing command needs no flag: it signs the explicit mode in the payload. Loopback admission endpoints are accepted only in fake mode, allowing local two-process admission tests. Overlay addresses still require the same private subnet allocations. The guest acceptance checker automatically reads the matching boot/config mode; admission, setup, status, acceptance and collective reports identify `attestation_type: "fake_tee"`.

Fake reports are forgeable and prove no hardware isolation, guest measurement or TCB state. Debug mode retains membership signatures, exact signed keys/context, TLS possession and fresh transcript checks, leases, authenticated overlay probes/heartbeats, timed firewall permissions and cleanup. Passing debug tests demonstrates those mechanisms, not confidential-computing attestation. Real workers continue to require DCAP and reject fake grants/evidence.

## Trusted configuration

Copy `worker-a.example.json` and `worker-b.example.json`, replacing the workload hash, signer public key, and endpoint addresses. Placeholders intentionally fail validation. The examples use `image_policy: "signed_membership"`; independently approve each final guest measurement before signing its membership. Use the actual mapped host ports for peer endpoints; local `listen_port` and `admission_port` name the guest's ports. For example, if a host maps UDP 51830 to guest UDP 51820, that host's peer entry uses `endpoint_port: 51830`.

The configuration, especially its signer key and authorization policy, must be protected by the measured guest image/spec or a separately verified trusted policy. Do not source the authority key or approved measurements from unsigned host runtime variables. A signature checked against an attacker-replaceable authority key establishes no authorization. Endpoint hints can change reachability but cannot replace signed member identities.

```bash
build/tee/cocoon-wireguard check-config --config worker-a.json
build/tee/cocoon-wireguard check-config --config worker-b.json
```

Both configurations must agree on cluster, workload digest, generation, and member allocation. Each has its own rank and overlay address. The first schema supports a complete configured group of 2–64 nodes, contiguous node ranks starting at zero, and one non-overlapping `/32` address per member within the configured RFC1918 subnet. Addresses are written without `/32` in JSON; routing is added later.

| Field | Meaning / bounds |
| --- | --- |
| `format` | Exactly `cocoon-wireguard-config-v1` |
| `interface` | Starts with `wg`, at most 15 ASCII identifier characters |
| `overlay_network` | Canonical RFC1918 CIDR, `/8` through `/30`; no host bits |
| `cluster_id`, `node_id` | 1–64 ASCII letters, digits, hyphens, or underscores |
| `workload_policy_sha256` | 32-byte digest encoded as 64 lowercase hexadecimal characters |
| `generation` | Positive integer, at most `INT64_MAX`; membership must match exactly |
| `node_rank`, `overlay_ipv4` | Unique configured rank and usable address in the overlay subnet |
| `listen_port`, `admission_port` | Local guest UDP and TCP ports, each 1024–65535 |
| `cert_base_name` | Absolute normalized certificate/key base path; existence is checked during admission, not configuration parsing |
| `membership_signer_public_key_b64` | Pinned 32-byte Ed25519 public key, canonical padded standard base64 |
| `attestation` | `type: "tdx"` or explicit debug `"fake_tee"`, with either `image_policy: "signed_membership"` or a nonempty bounded `allowed_image_hashes_hex` list; fake mode also requires `--no-tee` |
| `peers` | All other nodes, with unique IDs/ranks/addresses and unique UDP/TCP endpoint pairs; endpoints are canonical non-loopback unicast IPv4 outside the overlay subnet |
| `mtu` | Optional, 1280–1420; defaults to 1400; path-MTU checks follow during network setup |
| `keepalive_seconds` | Optional, 0–120; defaults to 25; zero disables keepalive |
| `timeouts` | Optional complete object; defaults: startup 60s, handshake 15s, lease 300s, renewal 60s, peer 30s |

Handshake timeout cannot exceed startup timeout; renewal and peer deadlines must be shorter than the lease. `run` additionally requires `peer_seconds >= 5` for kernel permission timeout margins. The parser rejects duplicate/unknown fields, wrong JSON types, duplicate allocations, network/broadcast addresses, invalid encodings, oversized documents, and excessive nesting. Network startup checks interface ownership and actual underlay conflicts before modifying the device.

For image authorization, choose exactly one form:

```json
{"type": "tdx", "image_policy": "signed_membership"}
```

or the original fixed policy:

```json
{"type": "tdx", "allowed_image_hashes_hex": ["64-lowercase-hexadecimal-characters"]}
```

Signed-membership mode delegates approval of each exact image hash to the measured Ed25519 operator key. It still requires a valid signed grant, DCAP verification, exact certificate/fresh-quote measurements and key/context binding. It does not trust self-reported images or unsigned policy changes. Unknown modes, mixed forms and empty fixed allowlists fail.

Use signed-membership mode for measured worker specs. Cocoon includes the spec in RTMR3 and its image hash; embedding that final hash inside the same spec would create a circular dependency. The operator approves finalized measurements in signed membership, outside the measured files. Fixed allowlists remain available with a separately protected policy outside the measurement being approved.

## Generate guest identities

Run on each intended CVM using its local configuration:

```bash
cocoon-wireguard enroll --config /spec/wireguard-config.json --output /run/wireguard-enrollment.json
```

The default private directory is `/run/cocoon-wireguard`, owned by the invoking user with exact mode 0700. The guest service will run as root. `identity.bin` and `identity.lock` use exact mode 0600. Enrollment creates an X25519/WireGuard private key and a separate random 32-byte boot identity; the exported JSON contains public fields only.

Keys survive process restarts during the same Linux boot. Saved state binds the kernel boot UUID and enrollment context (cluster, node/rank/address, workload, and signer), and includes a corruption checksum. A different boot, changed context, corrupt state, unsafe permissions, symlinked directories/files, or hard-linked private files causes rejection. State is never silently replaced. Generation can advance without rotating the same-boot key, allowing renewed membership.

Use `/run` in a CVM so private state is not persisted on host-visible disk. The checksum detects corruption; it is not protection against an adversary with guest-root access. Avoid restoring whole-VM snapshots with live keys; this step does not provide snapshot rollback protection. After reboot, export a new identity and authorize the new boot/key through enrollment.

For unprivileged local development, supply `--state-dir /tmp/cocoon-wireguard-a` and use a separate directory for B. Parent directories must exist. Only the final state directory is created. Development keys and exports do not prove that the program ran inside a CVM.

Public outputs are created exclusively: `--output` refuses an existing path. Export to a new filename on renewal or omit `--output` to emit public JSON to stdout. Private keys are never printed.

## Authorize membership

Maintain a separate Ed25519 membership signing key on the trusted enrollment authority, never in worker configuration. For a new authority, create the key under a restrictive umask and record its public key in the measured policy:

```bash
umask 077
openssl genpkey -algorithm ED25519 -out membership-signer.pem
openssl pkey -in membership-signer.pem -pubout -outform DER -out membership-signer.pub.der
tail -c 32 membership-signer.pub.der | base64 -w 0
```

The final command emits only the raw public key as base64. `sign-membership` requires the private PEM to be a regular file owned by the invoking user, exact mode 0600, without hard links or a final-component symlink. It accepts unencrypted Ed25519 PEM keys and performs no interactive password prompt.

Collect public enrollment exports from the two intended guests. Complete `membership.payload.example.json`: copy their exact node/rank/address, boot identities and WireGuard public keys; use independently approved image measurements; set the common workload digest and generation. Set `not_before` and `expires_at` to Unix seconds for the intended validity window. The interval must fit the configured lease (300 seconds by default).

An operator must verify guest evidence through a trusted enrollment process before issuing a real grant. Public exports still contain no evidence: this implementation does not automate an enrollment authority or provide a remote signing endpoint. Regardless of the enrollment process, `admit-peer` independently verifies fresh hardware evidence against the signed allocation before accepting a peer.

```bash
build/tee/cocoon-wireguard sign-membership \
  --payload membership.payload.json \
  --signing-key membership-signer.pem \
  --output membership.signed.json
```

Supply this signed envelope to each guest and check it against that guest's own saved identity:

```bash
cocoon-wireguard verify-membership \
  --config /spec/wireguard-config.json \
  --membership /run/membership.signed.json
```

Success prints the decoded public payload. A substituted signer/key/boot, wrong cluster/workload/generation, unexpected member allocation, unauthorized image claim, future/expired grant, excessive lease, or invalid signature fails. Expiry is exclusive: `not_before <= now < expires_at`. Time is the local wall clock and must be trustworthy; this offline check does not establish quote freshness, continuous revocation, monotonic lease supervision, or protection against clock rollback.

## Admit a pair of confidential guests

Provide each CVM with its own protected configuration, saved same-boot WireGuard identity, the common signed membership, and its Cocoon TDX certificate/key. The certificate files are `<cert_base_name>_cert.pem` and `<cert_base_name>_key.pem`; the private key must be owned by the invoking user with exact mode 0600. Admission reads the current pair for each session, checks that the keys match, and holds that certificate identity stable during the exchange. Certificate changes take effect on the next admission, including renewal in `run`; certificate generation/refresh still belongs to Cocoon's existing certificate service.

Run B first, then A, within the configured startup deadline:

```bash
# Inside worker B (rank 1): listens on the configured guest admission TCP port.
cocoon-wireguard admit-peer \
  --config /spec/wireguard-config.json \
  --membership /run/membership.signed.json \
  --peer worker-a \
  --output /run/admitted-a.json

# Inside worker A (rank 0): connects to B's configured mapped admission endpoint.
cocoon-wireguard admit-peer \
  --config /spec/wireguard-config.json \
  --membership /run/membership.signed.json \
  --peer worker-b \
  --output /run/admitted-b.json
```

The higher-ranked participant listens; the lower-ranked participant connects. Ensure the host forwards the peer's configured TCP admission endpoint to the guest's `admission_port`. A connection attempt uses bounded exponential backoff from 100ms to 2s. Once connected, certificate or protocol rejection fails the invocation. This diagnostic accepts one session and closes on completion or failure; `run` coordinates successive rank pairs and repeats fresh admission during renewal.

The command performs a full TLS 1.3 handshake using Cocoon's context helper and existing certificate OIDs. In real mode, both certificates must be self-signed Ed25519 certificates with exactly one critical TDX quote extension and one critical matching user-claims extension. Missing, duplicate, SEV, unexpected critical, expired, or invalid evidence fails. DCAP verifies the certificate quote without a shared cache; the resulting TLS public key binding, approved image, and platform attributes are checked before the admission exchange proceeds. Explicit fake mode uses the synthetic Intel/AMD formats described above.

Both guests then generate independent random 32-byte challenges. They check the exact expected peer ID and canonical signed-membership digest, and reconstruct the same binary admission record:

```text
23 bytes: ASCII "cocoon/wg-admission/v1" followed by one NUL
u32_be length + complete canonical membership bytes (the encoding specified below)
u16_be length + initiating node_id ASCII bytes
u16_be length + responding node_id ASCII bytes
32 bytes initiating challenge
32 bytes responding challenge
32 bytes initiating Ed25519 TLS public key
32 bytes responding Ed25519 TLS public key
32 bytes TLS exporter channel binding
```

The membership binds cluster, workload, generation, validity, all node/rank/boot identities, addresses, WireGuard public keys, and image claims. The channel binding uses `SSL_export_keying_material` with label `EXPERIMENTAL-cocoon-wg-admission-v1`, length 32, and no additional context. The connection and role binding prevents transferring a quote to another TLS session or reflecting the peer's quote as one's own.

Each guest requests a new remotely verifiable TDX quote with `REPORTDATA = SHA-512(record || prover_role)`, where the final role is one byte: 0 for the initiator, 1 for the responder. The process quotes only a record reconstructed from its own saved identity and verified membership. Its peer independently verifies DCAP signature/TCB status and unexpired collateral, then checks the full REPORTDATA, exact signed image, and platform attributes. The current conservative platform policy permits only attribute bits 28 (SEPT_VE_DISABLE), 30 (PKS), and 31 (KL), and requires an empty service-TD measurement. Debug, migration, profiling, partitioning, and unknown attributes are rejected. A wider platform policy requires an explicit implementation change and review.

The initiator sends its quote first; the responder verifies it before sending its own. Both exchange an acceptance message containing `SHA-256(record)` only after verifying their peer. Membership is checked again after verification and immediately before returning success, so expiry during admission fails. Frames have a 4-byte big-endian length and a one-byte type: hello=1, quote=2, acceptance=3. Payloads are bounded before allocation (hello at most 136 bytes, quote at most 32 KiB, acceptance exactly 32 bytes); truncated, unexpected, and malformed frames fail.

The total connection/admission work uses the configured startup deadline. TLS establishment also uses the shorter handshake deadline. Nonblocking sockets and separately owned evidence workers allow SIGINT/SIGTERM cancellation. Potentially blocking quote generation and DCAP verification run in an exec'd child with bounded input/output; timeout or cancellation kills and reaps the worker. A worker also requests termination when its parent dies. Real mode rejects unsupported builds before creating a listener or identity. Debug mode requires both `--no-tee` and an explicit fake configuration and uses synthetic Cocoon reports.

Success prints public JSON with `status: "peer_admitted"`, the verified peer key/boot/image, evidence and transcript hashes, membership generation, and expiry. **This is a diagnostic result of that session, not a reusable authorization token or proof of continuing connectivity.** `workload_ready` remains false. The command does not create an interface, install a WireGuard peer, or continuously enforce a lease. `run` consumes the live admission capability and performs network probes before enabling workload traffic.

Local tests use fixture evidence and the actual fake-TEE provider, including real two-process CLI admission. They cover real TLS exchanges, replay and context changes, certificate rejection, frame bounds, expiry, and cancellation/cleanup of a blocked verifier. They do not demonstrate genuine quote generation or successful DCAP verification. Before CVM deployment, build with the actual TDX/DCAP libraries and test this sequence on two approved guests, including substituted keys, old quotes, expired membership, and guest restart. The wall-clock and VM-suspension assumptions described above still apply.

Protocol references: [Intel TDX quote API](https://raw.githubusercontent.com/intel/confidential-computing.tee.dcap/main/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.h), [Linux TDX attribute definitions](https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/shared/tdx.h), and [OpenSSL TLS exporter](https://docs.openssl.org/4.1/man3/SSL_export_keying_material/).

## Signature format

The envelope has exactly `format`, `payload_b64`, `signature_b64`, and `signer_public_key_b64`. Its format is `cocoon-wireguard-signed-membership-v1`; the signer field must equal the configured trust anchor. Verification always uses that configured key.

Ed25519 signs the following bytes directly, with no separate digest and no JSON canonicalization:

```text
24 bytes: ASCII "cocoon/wg-membership/v1" followed by one NUL
u16_be length + cluster_id ASCII bytes
32 bytes: workload policy SHA-256
u64_be generation
u64_be not_before
u64_be expires_at
u16_be member_count
For each member sorted by node_id in ASCII order:
    u16_be length + node_id ASCII bytes
    u16_be node_rank
    32 bytes boot_id
    4 bytes IPv4 address in network order
    32 bytes WireGuard public key
    32 bytes image hash
```

Real v1 membership requires every JSON member to have `tee_type: "tdx"` and retains the binary domain above. Fake membership requires every member to have `tee_type: "fake_tee"` and replaces only that domain with `cocoon/wg-membership/fake-tee/v1` followed by NUL. The signed mode must match the configuration; mixed membership is rejected. Binary decoding rejects truncated, trailing, duplicate, invalid, or noncanonical records. JSON field order, whitespace, and member array order do not affect the signed payload. Signature and payload encodings use canonical padded standard base64. A membership signature authorizes values; fresh hardware evidence must still bind the admitted key and context.

Run the complete CLI integration test, including independent OpenSSL signature verification, with:

```bash
python3 tee/test/wireguard-cli.py build/tee/cocoon-wireguard
```

## Set up and probe the overlay (step 3)

Run this in each CVM, using that node's configuration and the same current signed membership:

```bash
cocoon-wireguard setup \
  --config /spec/wireguard-config.json \
  --membership /run/cluster-membership.json
```

The command runs in the foreground; start it on every configured rank during the startup window. Both ends must run `setup` for the install/probe barriers. `admit-peer` remains an admission-only diagnostic. All configured peers are required by `setup`, including entries marked `required: false`; `run` implements optional-peer handling.

Guest prerequisites are the kernel WireGuard module, network administration privileges, `/usr/sbin/ip`, `/usr/bin/wg`, and `/usr/sbin/nft`. UDP `listen_port` carries encrypted WireGuard packets, and TCP `admission_port` carries attested admission. Overlay UDP **51822** and **51823** are reserved for probes and heartbeats on every node; `listen_port` must differ from both. Neither control port needs an underlay/host mapping because both travel inside WireGuard. Host UDP mappings and the admission TCP mappings still need to be reachable.

Setup first checks live addresses and routes across routing tables for overlay overlap, checks underlay endpoint routes, and refuses to adopt an existing interface. It installs a closed firewall gate before creating its own interface. The interface has an ownership alias, the configured MTU, and the local overlay address as a `/32`. Each peer receives exactly its signed key, configured endpoint/keepalive, an `AllowedIPs` `/32`, and a separate Linux `/32` route **inside its freshly admitted TLS session**. Public admission JSON cannot be supplied as a setup grant. `wg` configures peers; `ip` configures links, addresses and routes. [WireGuard tool manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8).

The private key stays under the enrollment lock and reaches `wg` through a sealed, owner-only anonymous descriptor. Helpers receive fixed executable paths and explicit argument arrays, with no shell, unrelated inherited descriptors, or private key arguments. Their execution and output are bounded; helper diagnostics that might contain key material are not printed.

The retained firewall table is `inet cwg_<interface>`, for example `inet cwg_wg0`. Its input/output chains permit the two control UDP ports between exact local/peer addresses through the intended interface. Ordinary workload rules require membership in the timed `active_peers` and `ready_node` sets; `setup` leaves both empty. Remaining overlay source/destination traffic is dropped, preventing plaintext fallback to another interface. The forward chain always drops overlay traffic, including forwarded container packets: workloads currently need the guest's host network namespace, such as container host networking. There is no broad connection-tracking exemption. The service neither flushes the global ruleset nor overrides another table. A retained gate is reused only when its complete static rules match; only the exact previous step-3 closed gate can be upgraded, atomically. Existing firewall policy can still prevent traffic. These rules use nftables' structured JSON interface. [nftables JSON reference](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html).

After installation, both nodes exchange fresh challenges through connected UDP sockets bound to the WireGuard interface and local overlay address. HMAC-SHA256 uses a separate TLS exporter key tied to this admission transcript. Both directions must authenticate; malformed, reflected, stale or unauthenticated traffic cannot establish connectivity. Probe datagrams fill the configured inner IPv4 MTU and prohibit inner fragmentation. Retransmissions continue during a final TLS barrier, so packet loss does not turn a historical handshake into a successful connectivity result. A common rank-pair ordering coordinates meshes with more than two nodes.

Success prints a diagnostic snapshot with `status: "overlay_probed"`, public peer admission records, generation and expiry, and **`workload_ready: false`**. The gate remains closed. `--output FILE` writes the same snapshot exclusively; use a fresh path on each run. This file does not represent ongoing liveness or authorize workloads. Do not launch multinode inference from this status yet.

The command holds the device for at most the remaining signed lease using a monotonic deadline, also checking wall-clock expiry. It performs no renewal and no continuing peer liveness checks. SIGINT/SIGTERM, startup failure, probe failure, or lease expiry removes the owned interface, its routes and kernel peers while retaining the closed firewall. Lease expiry exits unsuccessfully; a signal after successful setup exits successfully. Cleanup checks the interface ownership alias, including when a helper times out after creating it.

A forced kill can leave the kernel interface and peers behind. `setup`'s retained gate still blocks workload traffic, and restart refuses to adopt that interface. Use `cleanup` below before restarting. Changing interface/CIDR/peer configuration requires explicitly reconciling retained gates; incompatible or modified guards are refused.

## Supervise and activate workloads (step 4)

Start `run` on every configured CVM during the startup window, using the same signed membership. Use one service process per enrolled identity; its lock prevents concurrent setup, enrollment mutation, or cleanup.

```bash
cocoon-wireguard run \
  --config /spec/wireguard-config.json \
  --membership /run/cluster-membership.json
```

Startup installs the closed guard and owned device, then admits and probes peers in a common rank-pair order. A single startup deadline covers setup, all initial admissions, and required-group readiness. Required-peer failure stops the service. An unavailable optional peer gets a bounded admission attempt and remains absent; an expired optional peer is removed from the kernel. At least one admitted, healthy peer is necessary even if all entries are optional.

Freshly admitted peers exchange authenticated challenges over overlay UDP 51823 once a second. The heartbeat key is derived from the live admission's exporter key using a separate HMAC domain, `cocoon/wg-heartbeat-key/v1` followed by NUL. Requests do not refresh liveness. Only an authenticated acknowledgment of an outstanding challenge counts, once, and its deadline starts when that challenge was issued. Delayed, reflected, previous-session, forged, and replayed packets cannot extend authorization. Each acknowledgment also reports whether the remote worker has completed its configured admission round. Required peers must report that state before workload access opens.

When ready, the service atomically refreshes nftables set elements every 500ms. Each peer permission ends at its signed lease or liveness bound; the local readiness element ends at the earliest required-peer or local lease bound. Integer nftables JSON timeouts are seconds. Permissions subtract a two-second helper/polling margin and round down, so access may close up to roughly three seconds early. Updates have a one-second helper deadline. Kernel element expiry removes permissions without waiting for userspace cleanup; a killed or stuck service cannot keep refreshing them. The outer WireGuard interface may remain until cleanup, but ordinary workload packets still lose their permission. [nftables element timeouts](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts).

Every second the ready service checks its interface ownership, UP state and MTU, exact installed peer keys/`AllowedIPs`, and static firewall rules. Authenticated heartbeats run while admission and evidence helpers wait, including renewal. Interface loss, changed inventory, required-peer expiry, bad renewal, or an invalid membership file closes the gate and stops the service. SIGINT/SIGTERM performs the same teardown and returns successfully. Other failures exit unsuccessfully.

### Renew a signed lease

Supply a new correctly signed grant before the current lease expires. Keep the same cluster, workload, generation, allocation, image, boot identities and WireGuard keys; increase `expires_at` and do not decrease `not_before`. The new validity interval must still fit `timeouts.lease_seconds`. Sign to a new filename, then atomically rename that completed envelope over `/run/cluster-membership.json` on each guest. Never rewrite the file in place: a partial or invalid file causes immediate withdrawal.

The service detects a changed grant and performs fresh mutual attestation and an MTU probe for every peer. Healthy existing traffic remains bounded by each peer's previous authorization until that peer completes admission under the new grant. Re-reading an unchanged grant never extends its monotonic expiry. Even without a changed grant, `renewal_seconds` schedules fresh reattestation; it cannot extend the operator's lease. Current certificate files are loaded again for each admission.

This first implementation requires coordinated grant delivery and renewal rounds across workers. A peer with a different membership digest rejects the admission; distribute the same grant to all ranks within their renewal window. There is no controller, staged two-grant protocol, or distributed agreement service yet. New member boot/key/image identities or a new generation require stopping the group, updating its protected configuration/membership as appropriate, and restarting through enrollment. An expired or rolled-back grant is rejected.

Wall time must be trustworthy when validating a grant, certificate and collateral. Within a running process, steady-clock deadlines prevent repeated grant reads or a wall-clock rollback from extending the anchored lease. Kernel timeout enforcement assumes guest timers progress and helper execution stays within the stated budget. VM suspension, full snapshot restore, host-controlled time, and replay across process restarts require a trusted time/epoch or controller design; local supervision does not provide complete rollback resistance. Guest root, the measured code/policy and firewall remain trusted.

### Status, systemd readiness and recovery

`run` atomically writes `<state-dir>/status.json` (default `/run/cocoon-wireguard/status.json`) with exact mode 0600 in the private directory. It contains public peer keys/boot IDs/measurements, state, generation, membership digest, lease expiry, heartbeat age and rejection reasons. Private keys and heartbeat secrets are never persisted in status. Stdout emits status on phase/readiness changes; the file refreshes about once a second. **Status is a diagnostic snapshot, not an authorization token or proof that the daemon is still alive.**

The [service template](systemd/cocoon-wireguard.service) uses `Type=notify`, a ten-second watchdog, preparation/cleanup before start and cleanup after stop, and the protected runtime directory. `READY=1` is sent only after required peers are healthy and kernel workload permissions are installed. Failure sends `STOPPING=1`, closes workload permissions, and removes the owned interface. systemd has no `READY=0` withdrawal protocol; service termination and a [consumer dependency](systemd/workload-dependency.conf.example) provide the stop contract. [systemd notifications](https://manpages.debian.org/trixie/libsystemd-dev/sd_notify.3.en.html).

The template allows VM sockets for TDX quote generation and IPv6 for collateral retrieval, although overlay peers remain IPv4. Intel's quote library can use a host QGS through `AF_VSOCK`; blocking that family would prevent that attestation path. It places the DCAP cache under the protected runtime directory using `AZDCAP_CACHE`, which Intel's provider supports. [Intel quote transport](https://raw.githubusercontent.com/intel/confidential-computing.tee.dcap/main/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c), [Intel collateral cache configuration](https://github.com/intel/confidential-computing.tee.dcap/blob/main/QuoteGeneration/qcnl/linux/sgx_default_qcnl.conf).

Install the dependency example as a drop-in for the actual inference service:

```ini
[Unit]
BindsTo=cocoon-wireguard.service
After=cocoon-wireguard.service
```

`After` waits for notification readiness; `BindsTo` stops a consumer when the overlay service becomes unavailable. The template retries a failed overlay service with bounded start-rate limits. It does not automatically relaunch a stopped inference group: after the overlay becomes ready again, explicitly restart the bound consumers or have the future job supervisor restart all ranks together. Guest preparation generates a start-timeout drop-in allowing two startup windows plus 60 seconds for preparation: waiting for membership and then admitting the group. Avoid adding `After=spec.service` when `/spec/init` synchronously starts the overlay, which would create an ordering cycle.

For crash recovery or a stopped diagnostic setup:

```bash
cocoon-wireguard cleanup --config /spec/wireguard-config.json
```

Cleanup acquires the saved identity lock before changing a live service's permissions, verifies/reinstalls the exact closed guard, clears timed sets, deletes only the interface with the enrolled ownership alias, and records stopped/unready status. It is idempotent and does not generate a missing enrollment key. Foreign interface ownership or incompatible firewall state is rejected, requiring administrator reconciliation. The retained fallback guards stay in place. Run cleanup with the same protected configuration and state directory; preserve the same-boot identity while restarting.

## Guest image and launcher integration (step 5)

The reproducible image includes `wireguard-tools`, `nftables`, `kmod` and Python 3, installs `/usr/bin/cocoon-wireguard` plus `/usr/bin/cocoon-wireguard-prepare`, and installs the notification service without enabling it globally. The package's global `nftables.service` stays disabled; the overlay manages its individual table alongside the existing INPUT policy. Rebuild the guest image with this configuration; a complete new image has not been built or booted in this workspace.

Before pruning the installed kernel, `mkosi.prepare` resolves the full `wireguard` and `nf_tables` dependency closures from its actual `modules.dep`/`modules.builtin`. It adds those files to the retained list, regenerates dependencies, checks the same closure afterward, and checks the version-specific load plan. Missing dependencies abort the build. Runtime preparation loads both modules and creates the nftables gate before opening input permissions. An older cache already containing a pruned kernel without WireGuard needs regeneration; it is rejected rather than producing an unusable image.

Opt in by adding `wireguard-config.json` to a custom measured worker spec or supplying it to the launcher. A runtime `WIREGUARD_ENABLED` variable does not opt in or authorize anything.

```bash
scripts/cocoon-launch \
  --wireguard-config worker-a.json \
  --backend sglang \
  --instance 0 \
  worker.conf
```

`--backend vllm` selects the other existing engine template. The selection is recorded in `inference-backend` inside the measured prepared spec; the default remains SGLang. This selects an existing single-node engine service, not distributed ranks, tensor/pipeline parallelism, head/worker roles or a cluster inference endpoint.

Equivalent optional INI fields:

```ini
[node]
wireguard_config = /path/to/worker-a.json
backend = sglang
# Optional host base ports; instance*10 is added:
wireguard_udp_port = 51820
wireguard_admission_port = 51821
```

Default host ports come from the measured local UDP `listen_port` and TCP `admission_port`. Host mappings add `instance * 10`; guest ports stay unchanged. For instance 1 with guest ports 51820/51821, the host accepts UDP **51830** and admission TCP **51831**. Put these actual host ports and routable host addresses in other workers' endpoint hints. The launcher reports both mappings and the membership-delivery path. It rejects port overflow, duplicate mappings, negative instances, non-worker use and local-mode WireGuard. `--no-tee` explicitly selects the separate fake mode described above. Optional `--udp PORT` follows the same general offset convention; these extra mappings do not create guest firewall permissions.

Bootstrap:

1. Pin the operator public key, workload/generation, allocation and image authorization mode in each worker configuration, then launch workers with those measured specs. This changes their final measurements; approve the finalized versions.
2. Guest preparation generates/reuses its same-boot identity and exports public JSON to `/run/cocoon-wireguard/enrollment.json`, also printing it to the specialization journal/console. Collect exports and independently verify the intended guest measurements. Exports alone remain insufficient evidence.
3. Sign one current membership containing the exact keys/boot identities, approved final measurements and allocation. Use the existing offline signing command; no signing key or enrollment authority runs inside a worker.
4. Deliver the completed envelope atomically to **`<prepared-spec-dir>/runtime/cluster-membership.json`** on every host. The launcher prints this directory. The guest reads it live through the read-only raw spec mount at **`/mnt/spec/runtime/cluster-membership.json`**. It does not use the `/spec/runtime` copy taken during initial spec preparation, so post-enrollment grants and renewals are visible without changing measured files.
5. The service waits for initial delivery for `startup_seconds`, verifies the saved local identity, then performs fresh mutual admission, probes and supervised activation. Inference and the worker runner start only after notification readiness. For renewal, atomically replace the file at that same host path on all ranks, following the coordinated-grant rules above.

For a prepared, approved payload:

```bash
mkdir -p /actual/prepared/spec/runtime
cocoon-wireguard sign-membership \
  --payload membership.payload.json --signing-key membership-signer.pem \
  --output /actual/prepared/spec/runtime/cluster-membership.next.json
mv /actual/prepared/spec/runtime/cluster-membership.next.json \
  /actual/prepared/spec/runtime/cluster-membership.json
```

`--wireguard-membership FILE` / `wireguard_membership = ...` can seed an already valid envelope into the prepared runtime directory; an old boot grant still fails after reboot. Updating the original source file supplied to that option does not update the prepared copy: renew at the path the launcher reports.

Preparation renders endpoint IPv4/UDP/TCP hints only. It compares every other field with measured JSON, normalizes quoted numeric endpoint placeholders, then applies the daemon's strict parser. Runtime changes to the signer, image policy, workload, generation, allocation, required flags, local ports, timeouts or certificate path fail before network mutation. The rendered configuration is `/run/spec/wireguard-config.json`, mode 0600. Worker integration also reserves admission TCP 8000 for inference and rejects WireGuard UDP 51822/51823.

Existing guest INPUT policy defaults to drop, so preparation adds exact marked rules for the configured outer UDP port, admission TCP port, and decrypted traffic on the owned overlay interface. The independent nftables gate is installed first and still enforces exact peers, workload leases and fallback drops; the base INPUT exception cannot override those drops. Post-stop cleanup removes only these marked INPUT rules after closing/removing the overlay and keeps the nftables guard. No global ruleset is flushed.

The opted-in backend uses Docker host networking and forces NCCL Socket transport with InfiniBand disabled and NCCL/Gloo socket interfaces set to WireGuard. NCCL uses an exact interface match (`-e NCCL_SOCKET_IFNAME==wg0` for `wg0`), IPv4 and separate OOB network selection disabled, following [NVIDIA's transport/interface options](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/env.html). Both the engine and `cocoon-worker-runner.service` bind to overlay availability. `/run/cocoon-wireguard/workload.env` exposes `COCOON_OVERLAY_INTERFACE`, `COCOON_OVERLAY_IPV4`, `COCOON_NODE_RANK`, and `COCOON_OVERLAY_STATUS` to the bound service processes. The router remains independently available. Existing backend image/version choices are retained.

If initial delivery misses a startup window or the group loses readiness, serving stays stopped. After supplying a current grant and restoring overlay readiness, explicitly start the bound engine and worker runner on all nodes together. For an otherwise completed bootstrap that timed out waiting for membership:

```bash
systemctl reset-failed cocoon-wireguard.service
systemctl start cocoon-wireguard.service
systemctl start cocoon-router.service cocoon-worker-runner.service cocoon-sglang.service
```

Use `cocoon-vllm.service` for that backend. To rerun specialization/configuration, stop the overlay and consumers first; preparation refuses to clean up an active identity. Automatic coherent rank restart remains future engine supervision work.

Step-5 checks passed 445 enrollment assertions, 1,042 admission/supervision assertions, 34 CLI checks and 13 guest/launcher integration tests. Integration tests use real enrollment/signature operations and the actual install script with build/archive commands mocked; network/service mutations are mocked. Sanitizers and SDK syntax checks passed. Systemd verified temporary local-path unit copies and specialization ordering with the external hardware service stubbed. The exact pinned Debian 6.19.10 module package was also used to verify the retained dependency closure and load plan; no host module was loaded. Full mkosi image build/boot and real TDX/kernel/inference traffic acceptance are outstanding.


## Kernel integration test

The local admission test includes synthetic-evidence admission, sealed-key ownership, command failure injection before/after mutations, route/interface conflicts, retained-gate validation/upgrade, peer rollback, and real loopback UDP probes at MTUs 1280, 1400 and 1420. It also checks packet loss and probe/heartbeat replay, delayed/out-of-order heartbeat handling, monotonic expiry, lease extension binding, optional-peer removal decisions, timed gate transactions, atomic status, notification/watchdog messages, ownership-safe crash cleanup, and teardown after gate failure. The explicit debug provider is also tested with actual Intel/AMD fake certificates, fresh challenges and mode isolation. Default production admission/setup/run still requires real TDX.

On a Linux test machine with root, network/mount namespace support, nftables, and a WireGuard-capable kernel:

```bash
sudo python3 tee/test/wireguard-network.py build/tee/test-wireguard-admission
```

The harness creates an outer network namespace and private mount namespace, then two worker namespaces connected by a veth pair. It checks real kernel WireGuard setup, the authenticated MTU probe, closed-gate blocking, authorized ordinary workload UDP, automatic kernel permission expiry while the interface stays up, cleanup/restart, and interface-loss detection. Its veth links never enter the host network namespace; `/run/netns` exists in a private temporary mount. Attestation is synthetic in this harness. A non-root invocation exits 77 with a skip explanation.

This workspace cannot create the required namespaces, including outside the application sandbox. The kernel integration harness has not been run here. Real TDX/DCAP admission and encrypted traffic between two actual CVMs still require hardware validation before enabling workloads.

Explicit fake-mode checks passed 456 enrollment assertions, 1,164 admission/supervision assertions, 34 existing CLI checks, 45 new actual fake-mode CLI checks, 16 guest/launcher tests and 17 acceptance tests. Actual gen-cert hashes were repeatable; ASan/UBSan, TDX-SDK syntax and the systemd fake-mode override passed. Full guest boot and kernel overlay traffic remain pending.
