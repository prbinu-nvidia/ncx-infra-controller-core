# SPDM Attestation Events and Failure Handling

**Implements:** [dsx-ai-factory/infra-controller#7706](https://github.com/dsx-ai-factory/infra-controller/issues/7706)

**Status:** Proposed

## Revision History

| Version | Date              | Modified By       | Description     |
| ------- | ----------------- | ----------------- | --------------- |
| 0.1     | November 23, 2026 | Binu Ramakrishnan | Initial version |
| 0.2     | November 25, 2026 | Binu Ramakrishnan | Review feedback: reuse `SpdmAttestationStatus`, typed failures for old results, and clear the standing waiver when SPDM is disabled |

## 1 Purpose

A consumer (for example, Maestro) needs to act on attestation results: quarantine a host whose evidence is rejected, update firmware, wait out a verifier outage, and release a host once it passes. Today the results stay inside NICo. Health alerts list problems as text, but never say that a machine passed.

This design:

- gives every failure a typed category and reason, and makes sure every attempt ends with a result (§3)
- defines when a failure blocks allocation, with a standing waiver, and what happens when SPDM is disabled (§4)
- publishes a message for each machine when its attestation changes, with a typed status, and returns the same message from an API (§5 to §7)

NICo reports results and blocks allocation of a machine with a failure. The consumer decides everything else ([attestation health alerts](attestation-health-alerts.md) §1.1). NICo never evicts a tenant because of attestation.

## 2 What exists

- **Health alerts.** The `attestation` health source is rebuilt when scheduling records a decision, when an attester finishes, and when `FailAttestation` or `WaiveAttestation` changes a finished result ([attestation health alerts](attestation-health-alerts.md) §5.1).
- **Managed-host events.** NICo publishes `ManagedHostState` to `{prefix}/{machineId}/state`, at most once, with a periodic republish. Nothing publishes attestation.
- **Read APIs.** `ListMachineAttestationStatuses` contacts the BMC. `GetAttestation` returns one job. No API returns a machine's stored attestation state.
- **Failures are text.** A failed attester stores only text, such as `Failed NRAS: ...`. Software cannot tell rejected evidence from a broken BMC.
- **Some errors retry forever.** Most Redfish errors, an unreachable verifier, and a verifier result that fails its checks are retried with no limit. The attester stays in progress, and nothing reports a failure.
- **The verifier result is only partly checked** (§3.2).
- **An unsupported firmware version passes.** When the Redfish driver answers `NotSupported` for an attester's firmware version, NICo records `Passed` without attesting.
- **A waiver covers one job.** The next attestation of a failing attester fails again.
- **Turning SPDM off leaves failure alerts**, and they keep blocking allocation.

## 3 Failures

### 3.1 Category and reason

A failure carries a category, a reason, and the existing text. `SpdmAttestationState::Failed(String)` becomes `Failed { category, reason, text }`, and states stored as plain text still load. The category list is short and fixed, so a consumer can handle every value. The reason list can grow.

| Category | Meaning |
| --- | --- |
| `Attester` | The BMC or device gave nothing usable to attest |
| `Verifier` | The verifier could not be reached, or refused the request. The machine is not in doubt |
| `Evidence` | The verifier rejected the evidence, or the evidence does not match the request |
| `AttestationResult` | NICo cannot trust the verifier's answer |
| `Operator` | An operator failed the job |
| `Unknown` | The failure was stored before this change, as text only. It has no reason |

| Reason | Category | Comes from | Today | Typical consumer action |
| --- | --- | --- | --- | --- |
| `CertificateLinkMissing` | `Attester` | The BMC gave no certificate link | Fails: `Could not get ca_certificate_link from DB` | Update the BMC firmware, then attest again |
| `EvidenceTargetMissing` | `Attester` | The BMC gave no evidence link | Fails: `Could not get evidence_target from DB` | Update the BMC firmware, then attest again |
| `FirmwareVersionUnavailable` | `Attester` | NICo's Redfish driver answers `NotSupported` for the firmware version (§3.4) | Records `Passed` | Check NICo's support for this BMC, or update the BMC firmware, then attest again |
| `EvidenceCollectionFailed` | `Attester` | The BMC's evidence collection task failed too many times, or did not stop in time when cancelled | Fails: `Too many retries triggering evidence collection`, or `Timed out waiting for BMC evidence collection to stop` | Reset or repair the BMC, then attest again |
| `RedfishRetriesExhausted` | `Attester` | Redfish errors passed the retry limit (§3.3) | Fails only when starting evidence collection; other steps retry forever | Reset or repair the BMC, then attest again |
| `VerifierRetriesExhausted` | `Verifier` | A timeout, connection error, or HTTP 5xx or 429 passed the retry limit (§3.3) | Retries forever | Do not quarantine. Attest again once the verifier is back |
| `VerifierRequestRejected` | `Verifier` | The verifier rejected the request with an HTTP 4xx other than 429 (§3.3) | Retries forever | Do not quarantine. Fix NICo's verifier settings, then attest again |
| `VerifierRejectedEvidence` | `Evidence` | The verifier said attestation did not pass | Fails: `Failed NRAS: ...` | Quarantine the host and investigate |
| `NonceMismatch` | `Evidence` | The result's nonce is not the one NICo sent (§3.2) | Not checked | Quarantine the host and investigate |
| `ResultSignatureInvalid` | `AttestationResult` | The signature, signing key, or algorithm check failed (§3.2) | Retries forever; the algorithm is not checked | Check the verifier and NICo's verifier settings. Do not blame the machine alone |
| `ResultExpired` | `AttestationResult` | The result has no expiry or has expired (§3.2) | Retries forever, and only when `validate_jwt_expiry` is on | Same |
| `ResultIssuerMismatch` | `AttestationResult` | The result's issuer is not the configured verifier (§3.2) | Not checked | Same |
| `ResultMalformed` | `AttestationResult` | The result lacks the overall result, the device list, or a device's result | Retries forever | Same |
| `FailedByOperator` | `Operator` | `FailAttestation` on an attester that passed or was waived. An attester that already failed keeps its own category and reason | Fails: `Failed by operator` | Follow the admin's reason |

A pass has no reason. It shows as status `Passed` (§5.1).

For `VerifierRejectedEvidence`, NICo forwards the reasons NRAS reports. NRAS gives no detailed reasons until [the NRAS interface upgrade](https://github.com/dsx-ai-factory/infra-controller/issues/7116).

The category and reason also appear in `GetAttestation` and in the health alert message.

### 3.2 Checking the verifier result

The verifier (NRAS) returns signed tokens (JWTs): one for the overall result and one for each device. Today NICo checks the signature, and checks the expiry only when `validate_jwt_expiry` is on. NICo adds:

| Check | Change | Reason on failure (§3.1) |
| --- | --- | --- |
| Algorithm | Require the algorithm set in the NRAS config, not the one in the token header | `ResultSignatureInvalid` |
| Expiry | Always require and check the expiry | `ResultExpired` |
| Nonce | Compare the result's nonce with the nonce NICo sent | `NonceMismatch` |
| Issuer | Require the issuer set in the NRAS config | `ResultIssuerMismatch` |

The algorithm and issuer are new fields in `nras::Config`. Every token is checked: the overall token and each device token.

A bad signature also gives `ResultSignatureInvalid`, and a malformed result gives `ResultMalformed`. Each fails the attester at once. The nonce field depends on [the NRAS interface upgrade](https://github.com/dsx-ai-factory/infra-controller/issues/7116).

### 3.3 Retry limits

Every step that calls the BMC or the verifier retries errors up to a limit, then fails the attester with `RedfishRetriesExhausted` or `VerifierRetriesExhausted`. Only verifier errors that may clear are retried: a timeout, a connection error, or an HTTP 5xx or 429. Any other HTTP 4xx fails at once with `VerifierRequestRejected`. For this, the NRAS client reports the HTTP status, which today it folds into text.

### 3.4 Unsupported firmware version

A `NotSupported` firmware version fails the attester with `FirmwareVersionUnavailable`. This lands after the standing waiver (§4.2), so an admin can waive machines whose BMC has no supported driver.

## 4 Enforcement

### 4.1 Overview

Two things change how a failure is enforced: a standing waiver (§4.2), and SPDM being disabled (§4.3). Both change only the `attestation` health source. Alerts from other health sources still block allocation.

| Standing waiver | SPDM disabled (§4.3) | A failure blocks allocation | Alerts |
| --- | --- | --- | --- |
| None | No | Yes | `SpdmAttestationFailed` |
| Set | No | No | `SpdmAttestationFailed` without `PreventAllocations`, plus `AttestationStandingWaiver` |
| None | Yes | No | `AttestationSpdmDisabled` |

Every failure blocks allocation the same way, whatever its category. Stored results are never changed.

### 4.2 Standing waiver

A standing waiver differs from `WaiveAttestation`, which waives the results of one job (`JobWaiver`); the next job can fail again.

An admin sets a standing waiver on a machine, with a reason, and clears it later. It is not part of attestation profiles, because a profile covers a whole hardware class and a waiver covers one machine. It has no expiry, and it stays through profile changes. Disabling SPDM clears it (§4.3). While SPDM is off, setting or clearing it is refused.

While it is set:

- attestation keeps running, and failure alerts stay, without `PreventAllocations`
- `AttestationStandingWaiver`, an informational alert, says who set it, when, why, and how many failure alerts the machine has
- a failure does not stop the host in `ManagedHostState::Failed`, and a host already stopped there continues

Clearing it restores `PreventAllocations` on current failures. It does not evict a tenant.

### 4.3 When SPDM is disabled

With SPDM off, the SPDM controller does not run. Unfinished jobs pause. `TriggerMachineAttestation`, `WaiveAttestation`, `FailAttestation`, and standing waiver changes are refused.

While SPDM is off, NICo marks every machine that has a standing waiver, or a job created since it was last marked, as SPDM disabled. It checks at startup and whenever it rebuilds a machine's health alerts. It records the time, clears the standing waiver, and replaces the failure alerts with `AttestationSpdmDisabled`, an informational alert that names any last failure, paused job, or cleared waiver.

Jobs created at or before that time no longer count for the status and health alerts, finished or not. `GetAttestation` still returns them. When SPDM is turned back on, the machine counts as not attested until its next scheduling decision, which also clears `AttestationSpdmDisabled`.

## 5 The event message

Each message carries the machine's full attestation state, with a typed status, what changed, and a revision. A consumer acts on the typed fields only. The failure text and alert messages are for people.

### 5.1 Status

The status uses the machine's selected attesters, the same ones its health alerts use. If the latest decision has an attester override, these are the attesters the override picked. Otherwise they are the attesters the profile selects.

The status reuses `SpdmAttestationStatus` (`InProgress`, `Waived`, `Passed`, `Failed`) and adds `NotAttested` and `SpdmDisabled`. Existing APIs never return the two new values. The first rule that matches wins:

| # | Status | When | Status reason |
| --- | --- | --- | --- |
| 1 | `InProgress` | A selected attester has an unfinished attempt | Empty |
| 2 | `Failed` | A selected attester has a failure, and no standing waiver is set | The failure categories, each once, in §3.1 order, such as `["Evidence"]` |
| 3 | `Waived` | A selected attester has a failure and a standing waiver is set, or a selected attester's result is waived | `["StandingWaiver"]`, `["JobWaiver"]`, or both |
| 4 | `SpdmDisabled` | The machine was marked SPDM disabled (§4.3), and has no scheduling decision since | Empty |
| 5 | `NotAttested` | The machine was removed, has no decision, its latest decision is not `Scheduled`, or a selected attester has no result | `["MachineRemoved"]`, `["NoDecision"]`, the `SpdmSchedulingOutcome` of the decision (such as `["PartiallySatisfied"]`), or `["NoResult"]` |
| 6 | `Passed` | The latest decision is `Scheduled`, and the verifier passed every selected attester | Empty |

A standing waiver shows as `Waived` only when it covers a failure. On a machine with no failure, the status does not change; the `AttestationStandingWaiver` alert and the standing waiver field still show it.

The status reason is always a list. Allocation follows the health alerts (§4), not the status.

When no job is running, the status matches the health alerts the message carries ([attestation health alerts](attestation-health-alerts.md) §5.2):

- `Failed` exactly when there is a `SpdmAttestationFailed` alert with `PreventAllocations`
- `Waived` with `StandingWaiver` exactly when there is an `AttestationStandingWaiver` alert and a `SpdmAttestationFailed` alert. `Waived` with only `JobWaiver` has no waiver alert
- `SpdmDisabled` exactly when there is an `AttestationSpdmDisabled` alert
- `NotAttested` with `NoAttestersFound` when there is `AttestationNoAttesters`, and with `PolicyMatchedNothing` or `PartiallySatisfied` when there is `AttestationPolicyUnsatisfied`

### 5.2 Fields

The message has fields for the whole machine, and one entry for each selected attester. The API returns the same fields.

| Field | Meaning |
| --- | --- |
| Machine ID | A host or a DPU |
| Machine created at | When NICo created the machine's record. A machine that is removed and found again gets a new value, and its revision starts over |
| Revision | Goes up by one with each message for the machine |
| Updated at | When NICo built this message |
| What changed | The change behind this message, and its job ID if it is about a job (§5.3) |
| Status, Status reason | §5.1 |
| Standing waiver | Who set it, when, and why. Absent if none |
| SPDM disabled at | When the machine was last marked SPDM disabled (§4.3). Absent if never |
| Scheduling decision | The stored decision, as in [attestation health alerts](attestation-health-alerts.md) §5.4. Absent if none |
| Health alerts | The machine's `attestation` health alerts. A cut alert message ends with `[truncated]` (§7) |
| Attesters | One entry for each selected attester |

Each attester entry has:

- the attester ID and its firmware version
- the job of its newest result that counts, the start and finish times, and the result: `Passed`, `Failed`, or `Waived`
- for a failure: the category, the reason, the text, and `text_truncated`, which is true when the text was cut (§7)
- the operator's waive or fail request on that job, if any
- any newer unfinished job, and its start time

An attester that leaves the selection is left out of the next message.

**Left out:** the BMC address and credentials, the nonce, certificates, evidence, and the raw verifier response.

### 5.3 What changed

NICo sends a message when a job starts, when a job finishes, and for changes not tied to a job. It does not send one when a single attester finishes.

| What changed | When |
| --- | --- |
| `DecisionRecorded` | Scheduling records a decision, from the machine's lifecycle or `TriggerMachineAttestation`, even one that creates no job |
| `JobFinished` | Every attester in the job has finished |
| `JobWaived` | `WaiveAttestation` waives a job. For an unfinished job, sent when the job ends, instead of `JobFinished` |
| `OperatorFailed` | `FailAttestation` fails a job. For an unfinished job, sent when the job ends, instead of `JobFinished` |
| `StandingWaiverSet`, `StandingWaiverCleared` | An admin sets or clears a standing waiver (§4.2) |
| `SpdmDisabled` | NICo marks the machine SPDM disabled (§4.3). If this clears a standing waiver, no separate `StandingWaiverCleared` is sent |
| `MachineRemoved` | `AdminForceDeleteMachine` removes the machine |

A `MachineRemoved` message is the machine's last: it has the next revision, no other state, and status `NotAttested` with `["MachineRemoved"]`.

### 5.4 Examples

Field names are illustrative; the AsyncAPI contract defines them (§8). An absent value is `null`.

**A failure.** Revision 42 from §6.3. The job finished: `HGX_IRoT_GPU_0` failed and `HGX_IRoT_GPU_1` passed:

```json
{
  "machine_id": "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag0l0",
  "machine_created_at": "2026-09-02T14:20:11Z",
  "revision": 42,
  "updated_at": "2026-11-23T18:05:10Z",
  "what_changed": { "kind": "JobFinished", "job_id": "0b7c6a52-3f4e-4c1e-9d2a-7a1f5e8c9b10" },
  "status": "Failed",
  "status_reason": ["Evidence"],
  "standing_waiver": null,
  "spdm_disabled_at": null,
  "scheduling_decision": {
    "outcome": "Scheduled",
    "hardware_class": "nvidia_dgx-h100",
    "used_any_fallback": false,
    "profile_version": "V7-T1760631000000000",
    "unsatisfied": null,
    "attester_override": null,
    "job_id": "0b7c6a52-3f4e-4c1e-9d2a-7a1f5e8c9b10"
  },
  "health_alerts": [
    {
      "id": "SpdmAttestationFailed",
      "target": "HGX_IRoT_GPU_0",
      "in_alert_since": "2026-11-23T18:03:52Z",
      "message": "Failed NRAS: ... (job 0b7c6a52-3f4e-4c1e-9d2a-7a1f5e8c9b10)",
      "classifications": ["PreventAllocations"]
    }
  ],
  "attesters": [
    {
      "attester_id": "HGX_IRoT_GPU_0",
      "firmware_version": "96.00.5E.00.01",
      "job_id": "0b7c6a52-3f4e-4c1e-9d2a-7a1f5e8c9b10",
      "started_at": "2026-11-23T18:01:07Z",
      "completed_at": "2026-11-23T18:03:52Z",
      "result": "Failed",
      "failure": {
        "category": "Evidence",
        "reason": "VerifierRejectedEvidence",
        "text": "Failed NRAS: ...",
        "text_truncated": false
      },
      "operator_request": null,
      "unfinished_job": null
    },
    {
      "attester_id": "HGX_IRoT_GPU_1",
      "firmware_version": "96.00.5E.00.01",
      "job_id": "0b7c6a52-3f4e-4c1e-9d2a-7a1f5e8c9b10",
      "started_at": "2026-11-23T18:01:07Z",
      "completed_at": "2026-11-23T18:05:10Z",
      "result": "Passed",
      "failure": null,
      "operator_request": null,
      "unfinished_job": null
    }
  ]
}
```

**A pass.** Revision 44 from §6.3, after the new job passed both attesters:

```json
{
  "machine_id": "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag0l0",
  "machine_created_at": "2026-09-02T14:20:11Z",
  "revision": 44,
  "updated_at": "2026-11-24T09:12:40Z",
  "what_changed": { "kind": "JobFinished", "job_id": "3e9d41c7-8a52-4b0f-a6c3-2f7e1d9b5a84" },
  "status": "Passed",
  "status_reason": [],
  "standing_waiver": null,
  "spdm_disabled_at": null,
  "scheduling_decision": {
    "outcome": "Scheduled",
    "hardware_class": "nvidia_dgx-h100",
    "used_any_fallback": false,
    "profile_version": "V7-T1760631000000000",
    "unsatisfied": null,
    "attester_override": null,
    "job_id": "3e9d41c7-8a52-4b0f-a6c3-2f7e1d9b5a84"
  },
  "health_alerts": [],
  "attesters": [
    {
      "attester_id": "HGX_IRoT_GPU_0",
      "firmware_version": "96.00.61.00.01",
      "job_id": "3e9d41c7-8a52-4b0f-a6c3-2f7e1d9b5a84",
      "started_at": "2026-11-24T09:10:02Z",
      "completed_at": "2026-11-24T09:12:40Z",
      "result": "Passed",
      "failure": null,
      "operator_request": null,
      "unfinished_job": null
    },
    {
      "attester_id": "HGX_IRoT_GPU_1",
      "firmware_version": "96.00.61.00.01",
      "job_id": "3e9d41c7-8a52-4b0f-a6c3-2f7e1d9b5a84",
      "started_at": "2026-11-24T09:10:02Z",
      "completed_at": "2026-11-24T09:12:31Z",
      "result": "Passed",
      "failure": null,
      "operator_request": null,
      "unfinished_job": null
    }
  ]
}
```

**Less attested than the profile asks for.** The machine from [attestation health alerts](attestation-health-alerts.md) §5.4, whose profile requires `HGX_ERoT_GPU_7`, which the BMC did not report. The attesters that matched were scheduled and passed:

```json
{
  "machine_id": "fm100htq3o0sd5n2kbeh2le4ckfoqpvh94ajd0mlt2gbaskqv8kh7p6mjgg",
  "machine_created_at": "2026-11-10T17:52:30Z",
  "revision": 7,
  "updated_at": "2026-11-10T18:15:02Z",
  "what_changed": { "kind": "JobFinished", "job_id": "7c3f1f0e-1d2a-4f7b-9a21-0b5e3c8d41a6" },
  "status": "NotAttested",
  "status_reason": ["PartiallySatisfied"],
  "standing_waiver": null,
  "spdm_disabled_at": null,
  "scheduling_decision": {
    "outcome": "PartiallySatisfied",
    "hardware_class": "nvidia_dgx-h100",
    "used_any_fallback": false,
    "profile_version": "V7-T1760631000000000",
    "unsatisfied": { "allowlist_patterns": [{ "exact": "HGX_ERoT_GPU_7" }] },
    "attester_override": null,
    "job_id": "7c3f1f0e-1d2a-4f7b-9a21-0b5e3c8d41a6"
  },
  "health_alerts": [
    {
      "id": "AttestationPolicyUnsatisfied",
      "target": "nvidia_dgx-h100",
      "in_alert_since": "2026-11-10T18:08:46.715149530Z",
      "message": "Attesting less than requested: attestation profile 'nvidia_dgx-h100' version V7-T1760631000000000 requires attesters matching 'HGX_ERoT_GPU_7', which the BMC did not report (job 7c3f1f0e-1d2a-4f7b-9a21-0b5e3c8d41a6).",
      "classifications": []
    }
  ],
  "attesters": [
    {
      "attester_id": "HGX_ERoT_GPU_6",
      "firmware_version": "96.00.61.00.01",
      "job_id": "7c3f1f0e-1d2a-4f7b-9a21-0b5e3c8d41a6",
      "started_at": "2026-11-10T18:08:46Z",
      "completed_at": "2026-11-10T18:15:02Z",
      "result": "Passed",
      "failure": null,
      "operator_request": null,
      "unfinished_job": null
    }
  ]
}
```

**A standing waiver.** The other path from revision 42 in §6.3: instead of attesting again, an admin sets a standing waiver. Only the fields that differ from revision 42 are shown. The failure stays visible, but no longer blocks allocation:

```json
{
  "revision": 43,
  "what_changed": { "kind": "StandingWaiverSet", "job_id": null },
  "status": "Waived",
  "status_reason": ["StandingWaiver"],
  "standing_waiver": {
    "set_by": "admin@example.com",
    "set_at": "2026-11-23T19:30:00Z",
    "reason": "Known GPU firmware issue, update scheduled"
  },
  "health_alerts": [
    {
      "id": "SpdmAttestationFailed",
      "target": "HGX_IRoT_GPU_0",
      "in_alert_since": "2026-11-23T18:03:52Z",
      "message": "Failed NRAS: ... (job 0b7c6a52-3f4e-4c1e-9d2a-7a1f5e8c9b10)",
      "classifications": []
    },
    {
      "id": "AttestationStandingWaiver",
      "target": null,
      "in_alert_since": "2026-11-23T19:30:00Z",
      "message": "Attestation waived by admin@example.com at 2026-11-23T19:30:00Z: Known GPU firmware issue, update scheduled. 1 failure alert.",
      "classifications": []
    }
  ]
}
```

**A removal.** The machine from §6.3, removed after revision 44:

```json
{
  "machine_id": "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag0l0",
  "machine_created_at": "2026-09-02T14:20:11Z",
  "revision": 45,
  "updated_at": "2026-11-25T08:00:00Z",
  "what_changed": { "kind": "MachineRemoved", "job_id": null },
  "status": "NotAttested",
  "status_reason": ["MachineRemoved"],
  "standing_waiver": null,
  "spdm_disabled_at": null,
  "scheduling_decision": null,
  "health_alerts": [],
  "attesters": []
}
```

## 6 Acting on events

A consumer acts on the current state, not only on the change, so a repeated or merged message is safe.

### 6.1 `Failed`

Use the action for each reason in §3.1. For an unknown reason, act on its category. For category `Unknown`, read the failure text. With several categories, handle each one.

### 6.2 Other statuses

For every status other than `Failed`, the consumer acts on the status and its status reason (§5.1). Only `Passed` releases a quarantine:

| Status | Status reason | Typical consumer action |
| --- | --- | --- |
| `InProgress` | Empty | Wait for the job, and keep any quarantine. An earlier failure still blocks allocation |
| `Waived` | `StandingWaiver`, `JobWaiver` | Keep it away from work that requires a pass. Record it for audit |
| `SpdmDisabled` | Empty | Attest again once SPDM is on |
| `NotAttested` | `MachineRemoved` | Drop the machine |
| `NotAttested` | `NoResult` | Attest again (§6.5) |
| `NotAttested` | `NoAttestersFound` | Check the hardware and BMC, then attest again |
| `NotAttested` | `PolicyMatchedNothing`, `PartiallySatisfied` | Fix the profile or the hardware, then attest again |
| `NotAttested` | `NoProfile`, `ClassNotRecorded` | Add a profile if the machine must be attested |
| `NotAttested` | `NoDecision` | Attest it (§6.5) if the work requires a pass |
| `NotAttested` | `AttestationDisabled` | None, unless the work requires a pass |
| `NotAttested` | `AttesterOverrideScheduled` | Attest again without an attester override |
| `Passed` | Empty | Release any quarantine, and allocate |

### 6.3 Quarantine and release

A host about to be assigned to a tenant reaches `ManagedHostState::PreAssignedMeasuring`. Its profile selects `HGX_IRoT_GPU_0` and `HGX_IRoT_GPU_1`:

| Revision | What changed | Status | Status reason |
| --- | --- | --- | --- |
| 41 | `DecisionRecorded` | `InProgress` | `[]` |
| 42 | `JobFinished` | `Failed` | `["Evidence"]` |

At revision 42 the consumer quarantines the host in its records; NICo already blocked allocation when `HGX_IRoT_GPU_0` failed. The host stops in `ManagedHostState::Failed`. After the fix, the consumer attests again (§6.5):

| Revision | What changed | Status | Status reason |
| --- | --- | --- | --- |
| 43 | `DecisionRecorded` | `InProgress` | `[]` |
| 44 | `JobFinished` | `Passed` | `[]` |

The consumer keeps the quarantine while the status is `InProgress`, and releases the host at revision 44.

### 6.4 Verifier outage

Many machines fail at once with `["Verifier"]`. The consumer does not quarantine them. It raises an alert for the verifier, and attests the machines again once the verifier is back (§6.5).

### 6.5 Attesting again, or periodically

A consumer can attest a machine at any time, in any machine state:

1. Call `TriggerMachineAttestation` and keep the job ID. A response without a job ID scheduled nothing; its outcome says why. With SPDM off, the call is refused.
2. Wait for the `JobFinished` message with that job ID, or `OperatorFailed` or `JobWaived` if an admin ended the job. Stop waiting on `SpdmDisabled`.
3. If a later message shows a different job in the scheduling decision, a newer job replaced yours, from another trigger or the machine's lifecycle. Follow the newer job.
4. Act on the status.

Do not use an attester override for periodic attestation: the status stays `NotAttested` (§6.2).

### 6.6 `InProgress` for too long

A job with many attesters can still take minutes. If no `JobFinished`, `JobWaived`, or `OperatorFailed` arrives well past the normal time, measured from the job's start time:

1. Read `GetMachineAttestationState`, in case a message was lost.
2. If it is still `InProgress`, tell the team that runs NICo: the SPDM controller may be down or stuck. The machine is not at fault, so do not quarantine it.
3. If the SPDM controller is running, an admin can end the job with `FailAttestation` or `WaiveAttestation`.

## 7 Delivery

**Topic.** `{prefix}/{machineId}/attestation`, next to the managed-host topic `{prefix}/{machineId}/state`. `{prefix}` defaults to `NICO/v1/machine`.

**Publishing.** At each change in §5.3, NICo builds the message and stores it in the same transaction as the health alerts, then publishes it after commit. While a job runs, the health alerts update after each attester, so they can be newer than the last message. For a removed machine, `AdminForceDeleteMachine` builds the `MachineRemoved` message before it deletes the machine.

**At most once.** A message can be lost, and close changes can go out as one message, so revisions can skip. A periodic republish sends each machine's last message again. `MachineRemoved` is not republished.

**Size.** Failure texts and alert messages are cut to a fixed length. Cut text ends with `[truncated]`, and `text_truncated` is set; the full text is in `GetAttestation`. If a message is still too large, NICo replaces every text with `[truncated]`. If even that is too large, NICo drops it with a metric and a log. NICo sets the MQTT client's packet limit explicitly; the default is 10 KB.

**Reading it back.** `GetMachineAttestationState` returns the machine's last message, from the database only. A machine with no message yet returns revision 0, `NotAttested`, and `["NoDecision"]`. An unknown machine returns `NotFound`. A consumer reads it at startup, and from time to time to catch up on lost messages.

**Order.** A consumer keeps the state with the newest machine created at, then the highest revision, and ignores older messages:

| Case | What the consumer does |
| --- | --- |
| Starts | Subscribes first, then reads the API for each machine it tracks, then applies only messages newer than what the API returned |
| Missed a message, or sees a revision gap | Applies the next message; it holds the full state |
| Older or repeated message | Ignores it |
| `MachineRemoved`, or `NotFound` from the API | Drops the machine |
| Newer machine created at, with the revision starting over | Replaces what it held |

## 8 Before publishing is turned on

Publishing is off by default, through a switch in `DsxExchangeEventBusConfig`. It stays off until:

- the topic and payload are in the AsyncAPI contract (`carbide.yaml`), with a version
- steps 1 and 2 of §9 have landed, so consumers get typed failures from the start

## 9 Implementation

Failure handling comes first. Events build on it.

| # | Change | Crate | Depends on |
| --- | --- | --- | --- |
| 1 | Failure category and reason, and the verifier result checks | `api-model`, `nras`, `spdm-controller`, `api-db`, `rpc`, `api-core` | |
| 2 | Retry limits, and the HTTP status from the NRAS client. Covered by the planned NRAS client and retry rules work | `nras`, `spdm-controller` | 1 |
| 3 | Standing waiver: column on `machines`, set and clear RPCs, CLI, `AttestationStandingWaiver`, state machine effects, and a gauge | `api-db` migration, `health-report`, `rpc`, `api-core`, `admin-cli`, `machine-controller` | |
| 4 | SPDM disabled: the time, `AttestationSpdmDisabled`, the startup check, and clearing the standing waiver | `api-db` migration, `health-report`, `api-core` | 3 |
| 5 | Fail an unsupported firmware version | `spdm-controller` | 1, 3 |
| 6 | Message model and status rules: add `NotAttested` and `SpdmDisabled` to `SpdmAttestationStatus`, reuse `SpdmSchedulingOutcome`, and store the last message in columns on `machines` | `api-model`, `rpc`, `api-db` migration | 1 |
| 7 | Build and store the message at each change in §5.3 | `api-db`, `machine-controller`, `spdm-controller`, `api-core` | 6 |
| 8 | `GetMachineAttestationState` RPC | `rpc`, `api-core` | 7 |
| 9 | Topic and payload in the AsyncAPI contract | External AsyncAPI repository | |
| 10 | Publisher: queue, republish, `MachineRemoved`, size limits, settings, and metrics | `state-controller`, `api-core`, `mqtt-common` | 7 |
| 11 | Public guide for consumers, from §5 to §7, registered in `docs/index.yml` | `docs` | 10 |

- In step 3, the lifecycle's SPDM poll and failed-recovery handlers treat a failure under a standing waiver as `Waived`.
- Step 7 covers the points steps 3 and 4 add: setting or clearing a standing waiver, and marking a machine SPDM disabled.
- Step 10 queues the machine ID after each commit: from the SPDM controller hook when a job finishes, the managed-host controller hook when scheduling records a decision, the RPC handlers, the startup check, and `AdminForceDeleteMachine`. The managed-host hook needs the previous state, which the state controller framework passes only in test builds today; step 10 changes that. The publisher reuses the event bus MQTT client and the managed-host republish settings.
- Step 10 can merge before step 9, but publishing stays off until §8 is met.
- Steps 3 and 4 add long-lived alerts. The republisher pacing fix in [attestation health alerts](attestation-health-alerts.md) §7 should land with them.

## 10 Not in this design

- Overriding a verifier verdict through appraisal policy
- More than one scheduling decision per machine
- Replacing `Failed` with a Wait substate

## 11 Open questions

- **Alert IDs.** `AttestationStandingWaiver` and `AttestationSpdmDisabled` are working names.
- **NRAS token settings.** The default algorithm and issuer in `nras::Config`.
- **NRAS errors.** Which NRAS errors mean rejected evidence rather than a bad request. The NRAS client work (§9 step 2) maps them to reasons; until then, an HTTP 4xx other than 429 gives `VerifierRequestRejected`.
