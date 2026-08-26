# entra-passkey-dynamic-migration

Report a Microsoft Entra tenant's Authentication Methods policy to the console,
and enable the `passkeyDynamicMigration` opt-out.

Windows PowerShell 5.1, Microsoft Graph, no module dependencies beyond
`Microsoft.Graph.Authentication`.

---

## What it changes

> **This script writes to your tenant.**
>
> It sets `optOutSettings.passkeyDynamicMigration` to `true` when the current
> value is `false` or `null`, then re-reads the policy to verify. That is the
> **only** setting it modifies — there is exactly one write call in the entire
> file, and everything else is read-only.
>
> Run it with `-ReportOnly` first to see the full report without changing
> anything.

`passkeyDynamicMigration` is a tenant-level opt-out related to Microsoft's
passkey rollout in the Authentication Methods policy. For what the setting
means and how long the opt-out is expected to remain available, see
[Microsoft's documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement).
This repository is concerned with reading and setting it safely.

---

## Quick start

```powershell
# Once, if you do not already have it. The full Graph SDK is not required.
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Connect. The scripts never connect or disconnect on your behalf.
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod","GroupMember.Read.All" -NoWelcome

Set-Location 'C:\path\to\entra-passkey-dynamic-migration'

# See everything, change nothing.
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly

# Apply the opt-out.
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1

Disconnect-MgGraph
```

A successful run ends with:

```text
FINAL VERIFIED STATUS
{
  "passkeyDynamicMigration": true
}
```

That block is printed **only** after the value has been re-read and confirmed.
Its absence means nothing was written — a `-ReportOnly` run never prints it.

---

## What the report shows

- **Migration state**, and whether legacy MFA and SSPR settings may still apply.
  Only `migrationComplete` is treated as authoritative; a `null` state is never
  assumed to mean migration finished.
- **Every authentication method** returned by the tenant, including disabled
  ones and any method the script does not recognise, with state *and* targeting
  side by side. A method enabled for one group is a very different posture from
  one enabled for everybody.
- **Group names** rather than raw GUIDs, where permissions allow.
- **Top-level policy settings** — registration campaign, system-preferred MFA,
  suspicious activity reporting — all read-only.
- **Observations**, worded descriptively rather than as compliance findings.
  Enabling an authentication method does not by itself require MFA; Conditional
  Access, Security Defaults and per-user MFA determine that, and none of them
  are visible from this policy.

---

## What it will never do

- Connect to, or disconnect from, Microsoft Graph. It uses your existing
  session, so a failed run never costs you your connection.
- Accept a tenant ID parameter. It acts on the tenant you are already connected
  to, and prints the account and tenant before doing anything.
- Enable or disable any authentication method, or change any targeting.
- Change the migration state, registration campaign, or system-preferred MFA.
- Touch Conditional Access, Security Defaults, per-user MFA, SSPR, or legacy MFA.
- Read per-user authentication methods or registration data. Policy
  configuration only — never user data.
- Write files. Output goes to the console.

If `Policy.ReadWrite.AuthenticationMethod` is missing it stops before changing
anything and prints the command needed to reconnect.

---

## Requirements

| | |
|---|---|
| PowerShell | Windows PowerShell 5.1 or later |
| Module | `Microsoft.Graph.Authentication` (the full Graph SDK is not needed) |
| Required scope | `Policy.ReadWrite.AuthenticationMethod` |
| Optional scope | `GroupMember.Read.All`, or any broader directory read scope, to resolve group names |
| Role | An administrator role that can read and write the Authentication Methods policy, such as Authentication Policy Administrator |

A granted scope is not sufficient on its own — without a qualifying directory
role the request returns `403` even with consent in place.

---

## Contents

| File | Purpose |
|---|---|
| `Set-EntraPasskeyDynamicMigrationOptOut.ps1` | The report and the opt-out. Supports `-ReportOnly` and `-Verbose`. |
| `Test-EntraPasskeyOptOutShape.ps1` | Read-only probe. Issues three GETs and nothing else; reports how your tenant returns `optOutSettings`. |
| [`docs/operator-guide.md`](docs/operator-guide.md) | Step-by-step: connecting, running, reading the output, troubleshooting. |
| [`docs/design-notes.md`](docs/design-notes.md) | Why the script behaves as it does, its safety boundaries, and what has been verified. |

---

## Verified behaviour

Exercised against a mocked Graph module under Windows PowerShell 5.1, and
confirmed against a live tenant:

- Sends no PATCH when the value is already `true`.
- Sets the value when it is `false`, `null`, or absent.
- Throws a terminating error if the value is not `true` afterwards.
- Handles `optOutSettings` present with a `null` value, and
  `policyMigrationState` being `null`, without mislabelling either.
- Reports methods it does not recognise instead of failing on them.
- Continues with raw GUIDs when no group-read scope is granted.
- Retries a throttled group lookup once, honouring `Retry-After`, then degrades
  without stalling the opt-out.
- Renders timestamps identically regardless of system locale.

### Why the verification step matters

`optOutSettings` does not appear in Microsoft's published Graph metadata. It is
returned by a plain `GET`, but `?$select=optOutSettings` fails with
`BadRequest` — the property is served without being part of Graph's queryable
model. OData services can silently ignore properties they do not model,
returning success without changing anything, so a `200` response does not prove
the write landed. Re-reading the value is the only way to know, and it turns a
silent no-op into a clear error.

---

## Licence

[MIT](LICENSE).

---

## Disclaimer

Not affiliated with or endorsed by Microsoft. Provided as-is, without warranty,
as stated in the licence. Review the script and run it with `-ReportOnly`
against a non-production tenant before using it in production.
