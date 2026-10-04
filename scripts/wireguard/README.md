# WireGuard configuration, enrollment, and admission

This implements steps 1 and 2 of the CVM overlay plan: strict configuration, local key generation, public enrollment exports, operator-signed membership, and fresh mutually attested peer admission. `cocoon-wireguard` provides setup commands and a bounded admission command for one configured pair. WireGuard interface configuration and continuous systemd supervision follow in later steps.

**An enrollment export is not attestation evidence.** It carries `attestation_status: "not_collected"`. The signing helper authorizes the supplied identities; it does not verify their hardware evidence. `verify-membership` verifies the operator signature, allocation, validity, and local identity, not remote TDX quotes. Live peer admission must independently verify evidence before enabling workload traffic.

## Build and check

```bash
cmake --build build --target cocoon-wireguard test-wireguard test-wireguard-admission -j 4
build/tee/test-wireguard
build/tee/test-wireguard-admission
build/tee/cocoon-wireguard --help
```

The executable is a Linux target and uses the existing OpenSSL, JSON, and Cocoon dependencies. Building and running the local tests requires no WireGuard tools, networking privileges, or TDX hardware. Actual `admit-peer` execution requires a build with real TDX/DCAP support and confidential guests. Packaging the executable and WireGuard tools into the guest image is a later step.

## Trusted configuration

Copy `worker-a.example.json` and `worker-b.example.json`, replacing the workload hash, signer public key, approved image hashes, and endpoint addresses. Placeholders intentionally fail validation. Use the actual mapped host ports for peer endpoints; local `listen_port` and `admission_port` name the guest's ports. For example, if a host maps UDP 51830 to guest UDP 51820, that host's peer entry uses `endpoint_port: 51830`.

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
| `attestation` | Exactly `type: "tdx"` and a nonempty bounded `allowed_image_hashes_hex` list; no permissive/fake platform modes |
| `peers` | All other nodes, with unique IDs/ranks/addresses and unique UDP/TCP endpoint pairs; endpoints are canonical non-loopback unicast IPv4 outside the overlay subnet |
| `mtu` | Optional, 1280–1420; defaults to 1400; path-MTU checks follow during network setup |
| `keepalive_seconds` | Optional, 0–120; defaults to 25; zero disables keepalive |
| `timeouts` | Optional complete object; defaults: startup 60s, handshake 15s, lease 300s, renewal 60s, peer 30s |

Handshake timeout cannot exceed startup timeout; renewal and peer deadlines must be shorter than the lease. The parser rejects duplicate/unknown fields, wrong JSON types, duplicate allocations, network/broadcast addresses, invalid encodings, oversized documents, and excessive nesting. It does not inspect live Linux interfaces/routes during step 1; ownership and actual underlay conflicts must be checked before network setup.

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

Provide each CVM with its own protected configuration, saved same-boot WireGuard identity, the common signed membership, and its Cocoon TDX certificate/key. The certificate files are `<cert_base_name>_cert.pem` and `<cert_base_name>_key.pem`; the private key must be owned by the invoking user with exact mode 0600. Admission reads the current pair for each session, checks that the keys match, and holds that certificate identity stable during the exchange. Certificate changes take effect on the next invocation.

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

The higher-ranked participant listens; the lower-ranked participant connects. Ensure the host forwards the peer's configured TCP admission endpoint to the guest's `admission_port`. A connection attempt uses bounded exponential backoff from 100ms to 2s. Once connected, certificate or protocol rejection fails the invocation. The listener accepts one session and closes on completion or failure; a multi-peer listener and ongoing renewal belong to supervision in step 4.

The command performs a full TLS 1.3 handshake using Cocoon's context helper and existing certificate OIDs. Both certificates must be self-signed Ed25519 certificates with exactly one critical TDX quote extension and one critical matching user-claims extension. Missing, duplicate, SEV, unexpected critical, expired, or invalid evidence fails. DCAP verifies the certificate quote without a shared cache; the resulting TLS public key binding, approved image, and platform attributes are checked before the admission exchange proceeds.

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

The total connection/admission work uses the configured startup deadline. TLS establishment also uses the shorter handshake deadline. Nonblocking sockets and separately owned evidence workers allow SIGINT/SIGTERM cancellation. Potentially blocking quote generation and DCAP verification run in an exec'd child with bounded input/output; timeout or cancellation kills and reaps the worker. A worker also requests termination when its parent dies. There is no production fake-verification switch; a build without the real SDK libraries rejects `admit-peer` before creating a listener or identity.

Success prints public JSON with `status: "peer_admitted"`, the verified peer key/boot/image, evidence and transcript hashes, membership generation, and expiry. **This is a diagnostic result of that session, not a reusable authorization token or proof of continuing connectivity.** `workload_ready` remains false. The command does not create an interface, install a WireGuard peer, or continuously enforce a lease. The next steps must consume admission in a supervised process and perform network probes before enabling workload traffic.

Local tests use synthetic evidence strictly inside the separate test executable. They cover real TLS exchanges, replay and context changes, certificate rejection, frame bounds, expiry, and cancellation/cleanup of a blocked verifier. They do not demonstrate genuine quote generation or successful DCAP verification. Before CVM deployment, build with the actual TDX/DCAP libraries and test this sequence on two approved guests, including substituted keys, old quotes, expired membership, and guest restart. The wall-clock and VM-suspension assumptions described above still apply.

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

The v1 schema permits TDX members only. The JSON input explicitly requires `tee_type: "tdx"`; the binary protocol domain fixes that platform for v1. Binary decoding rejects truncated, trailing, duplicate, invalid, or noncanonical records. JSON field order, whitespace, and member array order do not affect the signed payload. Signature and payload encodings use canonical padded standard base64. A membership signature authorizes values; fresh hardware evidence must still bind the admitted key and context.

Run the complete CLI integration test, including independent OpenSSL signature verification, with:

```bash
python3 tee/test/wireguard-cli.py build/tee/cocoon-wireguard
```
