# Voting Machine Architecture

## 1. Machine Platform

### Embedded Linux and Go Kiosk

Each polling station voting machine runs a hardened, embedded Linux distribution with a read-only root filesystem. The operating system is stripped to the minimum: no window manager, no interactive shell, no package manager, no remote login capability. The single user-space application is a full-screen kiosk written in Go. When the machine boots, the Go kiosk starts automatically and occupies the entire display. There is no mechanism for a user or operator to escape to a desktop or shell.

The machine has no printer, no paper path, no moving mechanical parts, and no removable optical media. The only outputs are the touchscreen display, the headphone jack for audio guidance, and the network interface for ballot sync. Physical complexity is minimized to reduce failure modes and to eliminate the side-channel of a printed ballot receipt.

### TPM-Based Software Attestation

The machine's trust anchor is a TPM 2.0 chip. At every boot, the bootloader measures the software image — the embedded Linux kernel, initrd, and Go kiosk binary — and the resulting SHA-256 hash is compared against a signed reference hash stored in the TPM's non-volatile memory. The reference hash is provisioned during the pre-election setup event (see Section 8, Hardware Requirements) and is signed by the election PKI's intermediate CA.

If the measured hash does not match the signed reference, the machine refuses to continue booting. The voter-facing display shows an error message, and the commission is alerted. No votes can be cast on a machine whose software integrity check has failed.

This mechanism replaces the role that paper played in traditional e-voting: paper provided a voter-verifiable physical record that was independent of the machine's software. TPM attestation provides an equivalent guarantee in a different direction — it proves to the election authority and to post-election auditors that the software running on election day was the specific, audited image, and that no modification occurred between the pre-election certification event and the moment of use. Compromising the machine's software requires either obtaining a private key held by the PKI or physically replacing hardware in a way that breaks tamper-evident seals, would be visible on camera, and would invalidate the TPM's hash chain.

The machine image is reproducibly built: the same source code and build environment always produce bit-for-bit identical output. The image hash is published before the election. Any party can independently rebuild the image and verify that the TPM is attesting to the audited software.

The audit log's first entry is signed by the TPM at boot, anchoring the entire log chain to the hardware attestation event.

---

## 2. Voter Flow

The following 11-step sequence describes the voter's experience at the polling station machine, as defined in the system design specification Section 5.2.

1. **Present ID to election commission.** The voter approaches the commission table and presents their Bulgarian identity card (лична карта). Commission members verify identity and check the electoral roll.

2. **Commission verifies eligibility and directs voter to machine.** After confirming the voter is eligible and has not yet voted, the commission completes the machine-tablet pairing protocol (see Section 3) and directs the voter to the assigned machine.

3. **Party selection screen.** The voter-facing touchscreen displays the full list of registered parties with large touch targets, party logos, and names in Bulgarian Cyrillic. The display is optimized for readability: minimum 44×44 px touch targets, high-contrast text, and an option to activate extra-large text or audio guidance.

4. **Select party.** The voter taps their chosen party. The selection is highlighted and a "Continue" control appears.

5. **Optional candidate preference screen.** If the selected party's candidate list is non-empty and the voter wishes to express a preference, the machine displays the party's candidate list. The voter may select one candidate or skip this step. Selecting a candidate is always optional.

6. **Review screen.** The machine displays a summary: "Вие избрахте: [party name] / [candidate name or 'Без предпочитание']". No other action is possible from this screen except confirming or restarting.

7. **Confirm or redo.** Two large physical buttons — green (confirm) and red (redo) — are the only inputs accepted on the review screen. Pressing red returns the voter to the party selection screen (step 3) with no selection retained. Pressing green advances to encryption.

8. **Encrypt ballot, generate proofs, assign ballot ID.** On green button press, the machine encrypts the ballot using exponential ElGamal over the Ristretto255 group with the election public key, generates the accompanying zero-knowledge proofs (ballot validity and candidate consistency Sigma proofs), and assigns a 256-bit cryptographically random ballot ID.

9. **Encrypted ballot queued to local SQLite.** The encrypted ballot, proofs, and ballot ID are written to the machine's local SQLite database. The write is atomic and durable. The voter flow does not depend on network availability at this step.

10. **Confirmation screen shows ballot ID.** The voter is shown their ballot ID in large, high-contrast text. They may photograph it or note it manually. This ID can later be used at `verify.izbori.bg` to confirm that their ballot appears on the public bulletin board (inclusion only — the ID never reveals ballot content). The ballot ID is displayed as both alphanumeric text and a QR code.

11. **Machine resets for next voter.** The confirmation screen remains visible for a configurable interval, then the machine returns to the idle state, clearing all in-memory session data. The next voter can only begin after the commission enters a new session code.

---

## 3. Machine-Tablet Pairing Protocol

The pairing protocol binds the voter's identity (known only to the commission tablet) to the ballot ID generated by the voting machine, without the machine ever learning the voter's identity. The following 7-step sequence is executed before each voter uses the machine.

1. **MRZ scan.** Before the voter approaches the machine, a commission member scans the voter's лична карта using a USB MRZ (Machine Readable Zone) reader attached to the commission tablet. The MRZ contains the voter's ЕГН (unified civil number), full name, document number, and check digits. Scanning eliminates manual entry errors and speeds queue throughput. Fallback: if the MRZ reader fails or the document is physically damaged, the commission member enters the ЕГН manually on the tablet.

2. **Tablet validates and generates session code.** The tablet validates MRZ check digits, extracts the ЕГН, and generates a 6-digit numeric session code using a cryptographically secure random number generator. The session code is displayed on the tablet screen for the commission member.

3. **Commission enters session code on machine keypad.** The commission member enters the 6-digit code on the voting machine's commission-side keypad. This keypad is physically separate from the voter-facing touchscreen — it is located on the side or rear of the machine enclosure and is not visible or accessible to the voter.

4. **Machine pairs ballot ID with session code.** The machine stores the session code in memory, associated with the ballot ID that will be generated for the next vote cast. The voter-facing screen transitions to "Ready" state. No information about the voter's identity is present on the machine at any point.

5. **Voter casts vote.** The voter completes the 11-step voting flow described in Section 2. On confirmation (green button press), the machine generates the ballot ID and internally associates it with the held session code.

6. **Machine transmits pairing to tablet.** After the ballot is encrypted and queued, the machine transmits `{session_code, ballot_id}` to the commission tablet via the local polling station network or Bluetooth LE. This transmission uses the machine's station key for message authentication.

7. **Tablet records ЕГН-to-ballot-ID mapping and forwards to Layer 1.** The commission tablet matches the received session code to the voter's ЕГН (held in the tablet's session record), records the `ЕГН → ballot_id` mapping, and forwards it to Layer 1's Collection Server. This is the only point at which voter identity and ballot ID are associated. The machine never learns the ЕГН; the Collection Server never learns the session code.

This design ensures no race conditions between adjacent machines, because each session code is unique to a single pairing event. It also ensures that the commission's explicit action (session code entry) is required before each vote, preventing a machine from accepting votes without a corresponding identity verification.

---

## 4. Offline Sync

Voting machines operate offline-first. All cryptographic operations and ballot storage function without network connectivity. Encrypted ballots accumulate in the local SQLite queue throughout the polling day. Sync to the Collection Server occurs opportunistically over the polling station's network connection when available, and falls back to physical USB transport if the network connection is unavailable for the entire day.

**Network sync (primary).** When connectivity is available, the machine establishes an mTLS connection to the Collection Server using its station certificate (issued pre-election, private key held in the TPM). Ballots are submitted in signed batches. The Collection Server acknowledges each batch, and the machine marks those entries as synced in its local database. Sync is incremental and resumable: if a sync is interrupted, it restarts from the last unacknowledged batch.

**USB sync (fallback).** If the polling station has no network connectivity throughout the day, ballot data is exported to a pre-provisioned USB drive at the end of voting hours. The USB transport follows the security protocol described in Section 5. Exported batches are identical in format to network-synced batches; the Collection Server processes them identically regardless of transport.

The SQLite queue is append-only during voting. Entries are never modified or deleted from the machine's local storage; only the sync status flag is updated on successful acknowledgement.

---

## 5. USB Sync Security

The USB sync path is a physical transport channel and must provide equivalent security guarantees to the network sync path. The following controls ensure integrity, authenticity, and chain of custody for physically transported ballot data.

**Station key in TPM.** Each machine's private key is generated inside the TPM during pre-election setup and never leaves the chip. The corresponding public key is registered with the Collection Server, associated with the station ID and constituency. All batch signatures are produced by the TPM.

**Batch format.** Each USB export batch has the structure: `{station_id, sequence_number, ballots[], batch_signature}`. The `sequence_number` is monotonically increasing per machine and is stored in TPM-protected non-volatile memory so it cannot be rolled back. The `batch_signature` covers all fields and is produced by the station key in the TPM.

**Pre-provisioned write-once USB drives.** USB drives are pre-provisioned by CIK before the election and distributed to polling stations. Each drive is registered with a specific station. The machine accepts only drives whose hardware serial matches the station's pre-registered media list; arbitrary USB drives are rejected. The drive is formatted as write-once: the machine appends the batch file and a cryptographic seal, after which the drive cannot be overwritten without detection.

**Collection Server validation.** On receiving a USB batch — either directly at a collection point or via the network after physical transport — the Collection Server verifies: (a) the station key signature is valid, (b) the station ID is registered and the certificate is not revoked, (c) the sequence number is strictly greater than the last accepted sequence number for that station, preventing replay attacks. Duplicate or out-of-order batches are rejected and logged.

**Two-person chain of custody.** USB export from the machine requires simultaneous authorization from two commission members, each pressing a dedicated physical button on the machine. The export event is logged with a timestamp, the batch sequence number, and a hash of the exported data. The physical USB drive is sealed in a tamper-evident envelope, signed by both commission members, and transported to the designated collection point under joint supervision. The chain of custody is documented on a physical form and a digital record in the audit log.

---

## 6. Audit Logs

Each machine maintains a tamper-evident local audit log that records operational events throughout the election day. The log records what the machine did and when — it never records vote content, party selections, or candidate choices.

**Logged events:**

- Boot: timestamp, software hash, TPM attestation result, self-test results
- Session start: timestamp, session code hash (not the code itself), commission keypad entry confirmed
- Vote cast: timestamp and ballot ID only — no party or candidate information
- Voter confirmed or cancelled (green/red button press)
- Encryption and proof generation completed: timestamp, duration
- Network sync events: connection established, batch sequence number, ballot count transmitted, acknowledgement received
- USB export: initiated, batch sequence number, ballot count, two-person authorization recorded
- Errors: hardware failures, network timeouts, proof validation failures, TPM attestation failures, rejected USB media
- Power events: battery switchover, power restore, sleep, shutdown

**Hash-chained structure.** Each log entry is hash-chained to the previous: `entry_hash = SHA-256(previous_hash || entry_data || timestamp)`. The chain is anchored to the TPM: the first entry after boot is signed by the TPM using the station key. This means the TPM's boot attestation (software hash verification) and the log's tamper evidence are bound together — a valid log chain implies the machine was running attested software from the moment the log began.

**Export.** Logs are exported alongside ballot batches in both network sync and USB sync operations. Logs can also be exported independently for audit purposes, without including ballot data.

**Central validation.** After the election, all machine logs are collected centrally. The Collection Server validates the full hash chain of each log against the TPM anchor signature from that machine's boot record. A broken chain — indicating that log entries were modified, inserted, or deleted after the fact — causes the affected machine's ballots to be quarantined pending investigation. Logs that pass chain validation are archived as part of the permanent election record.

---

## 7. Polling Station Cameras

Bulgarian polling stations are required by law to have continuous video surveillance during elections. The otvoren-vot hardware requirements specification defines integration constraints for the camera environment to preserve voter privacy while maintaining physical security.

**Privacy constraints.** Cameras must not have a direct line of sight to the voter-facing screen of any voting machine. The voter's ballot selection must not be visible in any camera's field of view. Camera placement is specified in the hardware requirements document with a recommended room layout diagram showing permissible mounting positions.

**What cameras should capture.** The camera system should provide full coverage of: the polling station entrance and commission table (to record voter arrivals and identity verification), the voting machine area from behind and from the side (to record physical access to machine ports, seal integrity, and the approach of voters without capturing screen content), and commission procedures including MRZ scanning and session code entry on the machine's commission keypad.

**Recording and retention.** Cameras record continuously from the opening of polls to the end of post-voting procedures. Footage is stored locally at the polling station on a dedicated recording device that is physically separate from the voting machine. Footage is retained for a minimum of six months to cover legal challenge periods. Access to recordings requires a judicial order or a formal administrative decision by CIK. The camera hardware and recording infrastructure are outside the software scope of otvoren-vot; these are integration requirements only.

---

## 8. Hardware Requirements

The following specification defines the minimum hardware configuration for a compliant otvoren-vot voting machine. Procurement documentation must reference these requirements.

| Component | Requirement |
|-----------|-------------|
| CPU | 64-bit x86-64 or ARM64; minimum 4 cores at 1.5 GHz |
| RAM | Minimum 4 GB ECC |
| Storage | 32 GB eMMC or SSD; read-only root filesystem capability required |
| TPM | TPM 2.0 (TCG spec), with non-volatile storage for station key and reference hash; key generation and signing performed internally |
| Touchscreen | 15–17 inch diagonal; minimum 1080p resolution; minimum 500 cd/m² brightness; wide viewing angle with privacy filter installed (limits horizontal viewing cone to prevent side-viewing of the screen) |
| Physical buttons | Minimum 2 large physical buttons (green confirm, red cancel) connected via GPIO or USB HID; button actuation force and size must meet accessibility requirements |
| Commission keypad | Separate numeric keypad (0–9 plus confirm) mounted on the side or rear of the enclosure; not accessible from the voter-facing side |
| MRZ reader | USB-attached, ISO/IEC 7501-1 compliant; mounted at the commission table (not on the voting machine itself); fallback to manual ЕГН entry on tablet |
| Tamper-evident enclosure | All external ports (USB, Ethernet, power) sealed with numbered tamper-evident labels; enclosure design must prevent access to internal components without breaking a seal |
| Battery backup | Minimum 30 minutes of operation on battery; automatic switchover on mains failure without interrupting a vote in progress |
| Network interface | Ethernet (RJ-45, 1 Gbps) and/or Wi-Fi 802.11ac (5 GHz); pre-configured with Collection Server IP addresses (no DNS dependency) |
| Environmental | Operating range: 0–40°C, 20–80% relative humidity non-condensing |
| Audio output | 3.5 mm headphone jack for accessibility audio guidance |

---

## 9. Accessibility

The voting machine includes dedicated accessibility features that can be activated by any voter. Accessibility features do not require assistance from commission members and do not reveal the voter's accessibility needs to anyone observing the machine from a distance.

**Large text mode with high contrast.** An accessibility button on the machine frame (not on the voter-facing touchscreen to prevent accidental activation) activates extra-large text mode. In this mode, text size is significantly increased and the display switches to a high-contrast color scheme meeting WCAG AAA contrast ratios. All party names and candidate names remain fully legible.

**Audio guidance.** For blind or visually impaired voters, the machine provides audio guidance via a standard 3.5 mm headphone jack. When headphones are connected, the machine announces each screen's content, available options, and selected choices through the headphones only — no audio is emitted from external speakers. Navigation in audio mode uses two dedicated physical hardware buttons (NEXT and SELECT) so that the voter can operate the machine entirely by touch and sound, without needing to locate on-screen controls.

**Ballot ID presentation.** On the confirmation screen, the ballot ID is displayed in large, high-contrast text alongside a QR code. Voters using audio mode hear the ballot ID read aloud through their headphones. The touchscreen touch targets for all interactive elements meet the WCAG minimum of 44×44 px. No time limit is imposed on the confirmation screen; the ballot ID remains visible until the voter moves away and the session times out.
