# Entra Passkey Dynamic Migration - Design Notes

Why `Set-EntraPasskeyDynamicMigrationOptOut.ps1` behaves the way it does, and
what it deliberately refuses to do.

If you only want to run it, read
[operator-guide.md](operator-guide.md)
instead. This document is for anyone reviewing the script before trusting it
against their own tenant.

---

## What the script does

It reports the tenant's modern Authentication Methods policy to the console,
then sets `optOutSettings.passkeyDynamicMigration` to `true` — but only when the
current value is `false` or `null`. It re-reads the policy afterwards and throws
if the value is not `true`.

**`passkeyDynamicMigration` is the only tenant setting it modifies.** There is
exactly one write call in the entire file. Everything else is read-only.

Pass `-ReportOnly` to produce the full report and stop before the write.

---

## Safety boundaries

The script does not:

- Connect to Microsoft Graph, or disconnect from it. It uses your existing
  session, so a failed run never costs you your connection.
- Accept a tenant ID parameter. It operates on whatever tenant you are already
  connected to, and prints the account and tenant before doing anything.
- Change the Authentication Methods migration state.
- Enable or disable any authentication method.
- Change any include or exclude target.
- Change Registration Campaign or system-preferred MFA settings.
- Touch Conditional Access, Security Defaults, per-user MFA, SSPR, or legacy MFA.
- Retrieve per-user authentication methods or registration reports. It reads
  policy configuration only, never user data.
- Write any file. Output goes to the console.

It stops before changing anything if `Policy.ReadWrite.AuthenticationMethod` is
missing, and prints the exact command needed to reconnect.

---

## Design decisions and their reasoning

### The report is sourced from the beta endpoint

`passkeyDynamicMigration` exists only in beta, so the script has to call beta
regardless. The report is sourced from the same response because beta returns
strictly more: in a tenant tested in August 2026, beta returned **12 method
configurations against v1.0's 10**, with `HardwareOath` and
`FederatedIdentityCredential` visible only in beta. Passkey profile details are
likewise beta-only.

Sourcing the report from v1.0 would mean reporting less while calling beta
anyway.

### Only `migrationComplete` is treated as authoritative

`policyMigrationState` determines whether legacy MFA and SSPR settings still
apply alongside the modern policy. A missing or unrecognised value is never
assumed to mean migration finished.

| Graph value | Reported as |
|---|---|
| `migrationComplete` | Migration Complete - modern policy is authoritative |
| `migrationInProgress` | Migration In Progress - legacy settings may also apply |
| `preMigration` | Pre-Migration - legacy settings may also apply |
| `null`, missing, unknown | **Not Confirmed** - legacy settings may also apply |

Anything other than `migrationComplete` prints a prominent warning, and the
report continues.

### Targeting is always shown next to state

A method's `state` alone does not tell you who can use it. The report always
shows include and exclude targets alongside the state, because `enabled` with a
narrow include target is a very different posture from `enabled` for all users.

The same reasoning applies one level deeper. Several settings live on individual
targets rather than on the method, and are rendered per target:

| Setting | Lives on |
|---|---|
| Authentication mode (Microsoft Authenticator) | each include target |
| Allowed passkey profiles (Passkey/FIDO2) | each include target |
| Usable for sign-in (SMS) | each include target |

Microsoft Authenticator feature settings such as number matching carry their own
targets too, so they render as `enabled (applies to: ...)` rather than a bare
`enabled`.

### Group names are resolved, and failure is never fatal

Group targets are GUIDs. The script resolves them to display names, querying
only `id` and `displayName`, and caches each group so it is fetched at most once
per run.

Two IDs are translated locally without any Graph call:

| Target ID | Shown as |
|---|---|
| `all_users` | All users |
| `00000000-0000-0000-0000-000000000000` | None |

If a group cannot be resolved — deleted, inaccessible, or no group-read scope
granted — the report continues and falls back to the raw GUID. Group resolution
is a convenience; it never blocks the opt-out.

A throttled lookup (HTTP 429) is retried once, honouring `Retry-After`. If it is
still throttled, that group is labelled `Group lookup throttled (<GUID>)` rather
than `Unresolved group (<GUID>)`, so a live group is never presented as deleted.
Once a retry proves useless the script stops retrying for the rest of the run,
so a heavily throttled tenant cannot stall the opt-out behind dozens of waits.

### Unknown methods must never cause a failure

Microsoft adds authentication methods over time. Recognised methods get friendly
names and curated settings; anything unrecognised still appears with its Graph
ID, type, state, and targets.

| Method | Reported settings |
|---|---|
| Microsoft Authenticator | Software OATH allowance, number matching, app information, location information |
| Passkey/FIDO2 | Default passkey profile, self-service registration, attestation, key restrictions and count |
| SMS | Common properties (sign-in availability is per target) |
| Voice | Office-phone allowance |
| Temporary Access Pass | One-time use, length, default/minimum/maximum lifetime |
| Email OTP | External ID allowance |
| Certificate authentication | Default mode, rule count, certificate binding count |
| QR code and PIN | PIN length, QR code lifetime |
| Software OATH, Hardware OATH, Verifiable credentials | Common properties only |
| External authentication method | Display name and application ID |
| Federated identity credential | Common properties; Microsoft has published no settings for it |
| Any unknown method | Graph ID, type, and common properties |

Method-specific properties are optional in Graph responses, so every access is
defensive. The script runs under `Set-StrictMode -Version Latest`, where reading
a property that does not exist is an error rather than a silent `null`.

### Observations are descriptive, not a compliance verdict

The report ends with observations covering things like SMS or voice being
enabled, Microsoft Authenticator or passkeys being disabled, passkeys not
targeting all users, unresolved groups, and an already-enabled Registration
Campaign.

These are deliberately worded as observations rather than findings. **Enabling
an authentication method does not by itself require MFA** — Conditional Access,
Security Defaults, per-user MFA and other controls determine that, and none of
them are visible from this policy alone.

### Read-only top-level settings

Policy version, last modified time, Registration Campaign, system-preferred MFA,
and suspicious activity reporting are all reported and never modified. In
particular, the opt-out does not disable a Registration Campaign that is already
configured; the report just makes its state visible.

Timestamps are rendered as ISO 8601 UTC. Graph returns these as date objects,
and formatting them with the local culture would produce an ambiguous date with
no timezone.

---

## The opt-out itself

```text
If passkeyDynamicMigration is true:
    report that no change is required

If it is false, null, or missing:
    PATCH optOutSettings.passkeyDynamicMigration to true

Re-read the policy.
If the final value is not true:
    throw a terminating verification error
```

PATCH body:

```json
{
  "optOutSettings": {
    "passkeyDynamicMigration": true
  }
}
```

A successful run ends with:

```text
FINAL VERIFIED STATUS
{
  "passkeyDynamicMigration": true
}
```

That block is only printed after the value has been re-read and confirmed. Its
absence means nothing was written — a `-ReportOnly` run never prints it.

### Why the re-read is mandatory

`optOutSettings` does not appear in Microsoft's published Graph metadata. It is
returned by a plain `GET`, but `?$select=optOutSettings` fails with
`BadRequest`, which means the property is served in the payload without being
part of Graph's queryable model.

OData services can silently ignore properties they do not model, returning
success without changing anything. A `200` response therefore does not prove the
write landed. Re-reading the value is the only way to know, and it turns a
silent no-op into a clear terminating error.

For the record, the PATCH does work: confirmed against a live tenant, with the
policy's `lastModifiedDateTime` independently advancing to match.

---

## Requirements

- Windows PowerShell 5.1 or later.
- The `Microsoft.Graph.Authentication` module. The full Graph SDK is not needed;
  the script calls `Invoke-MgGraphRequest` directly.
- An existing Graph session with `Policy.ReadWrite.AuthenticationMethod`.
  `GroupMember.Read.All` (or a broader directory read scope) is optional and
  only enables group name resolution.

| Endpoint | Purpose |
|---|---|
| `GET /beta/policies/authenticationmethodspolicy` | Read the policy and `passkeyDynamicMigration` |
| `PATCH /beta/policies/authenticationmethodspolicy` | The single authorised write |
| `GET /v1.0/groups/{id}?$select=id,displayName` | Resolve a group name |

---

## Verified behaviour

Exercised against a mocked Graph module under Windows PowerShell 5.1, and
confirmed against a live tenant:

- Sends no PATCH when the value is already `true`.
- Sets the value when it is `false`, `null`, or entirely absent.
- Throws if the value is not `true` after the operation.
- Handles `optOutSettings` present with a `null` value.
- Handles `policyMigrationState` being `null` without mislabelling it complete.
- Reports every returned method, including disabled and unrecognised ones.
- Survives a policy where most optional properties are missing.
- Survives a single method returned as an object rather than a collection, and
  targets returned the same way.
- Continues with raw GUIDs when no group-read scope is present.
- Retries a throttled group lookup once, then degrades without stalling.
- Completes the opt-out even when every group lookup is throttled.
- Stops before any change when the required scope is missing or no session
  exists.
- Renders timestamps identically under `en-US`, `en-GB`, and `de-DE`.
- Leaves the Graph session connected, and creates no files.

---

## Internal structure

Raw retrieval, interpretation, console presentation, and the single mutation are
kept separate:

```text
Test-RequiredGraphContext
Get-AuthenticationMethodsPolicy
Get-MigrationStateDisplay
Get-ThrottleRetrySeconds
Get-TargetDisplayName
Resolve-PolicyGroupTargets
Format-TargetList
Format-FeatureSetting
Get-AuthenticationMethodFriendlyName
Show-AuthenticationMethodDetails
Show-AdditionalPolicySettings
Show-PolicyObservations
Get-PasskeyDynamicMigrationStatus
Set-PasskeyDynamicMigrationOptOut
Test-PasskeyDynamicMigrationStatus
```

---

## Reference documentation

- [Get authenticationMethodsPolicy](https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get?view=graph-rest-1.0)
- [Migrate MFA and SSPR settings to the Authentication Methods policy](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage)
- [Passkeys by default and retirement of Microsoft-provided SMS and voice](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement)
- [Get group](https://learn.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
