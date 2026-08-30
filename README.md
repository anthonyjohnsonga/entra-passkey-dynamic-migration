# entra-passkey-dynamic-migration

> Read a Microsoft Entra tenant's Authentication Methods policy in full — then
> flip the `passkeyDynamicMigration` opt-out, and prove it landed.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-beta-0078D4?style=flat-square)](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta)
[![Writes](https://img.shields.io/badge/writes-1%20setting-important?style=flat-square)](#the-one-thing-it-changes)
[![Licence](https://img.shields.io/badge/licence-MIT-green?style=flat-square)](LICENSE)

One script, one write call, no dependencies beyond
`Microsoft.Graph.Authentication`. A successful run ends like this — and prints
this block **only** after re-reading the value from Graph to confirm it:

```text
FINAL VERIFIED STATUS
{
  "passkeyDynamicMigration": true
}
```

## The one thing it changes

> [!WARNING]
> **This script writes to your tenant.**
>
> It sets `optOutSettings.passkeyDynamicMigration` to `true` when the current
> value is `false` or `null`, then re-reads the policy to verify. That is the
> **only** setting it modifies — there is exactly one write call in the entire
> file. Everything else is read-only.

> [!TIP]
> Run it with `-ReportOnly` first. You get the entire report and nothing is
> changed.

`passkeyDynamicMigration` is a tenant-level opt-out related to Microsoft's
passkey rollout in the Authentication Methods policy. For what the setting means
and how long the opt-out is expected to remain available, see
[Microsoft's documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement).
This repository is concerned with reading and setting it safely.

## Start here

```powershell
# 1. Once, if you do not already have it. The full Graph SDK is not required.
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# 2. Connect. The scripts never connect or disconnect on your behalf.
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod","GroupMember.Read.All" -NoWelcome

Set-Location 'C:\path\to\entra-passkey-dynamic-migration'

# 3. See everything, change nothing.
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly

# 4. Apply the opt-out.
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1

Disconnect-MgGraph
```

Add `-CsvPath .\tenant.csv` to keep the whole report as a CSV alongside the
console output. `-NoColor` disables colour, as does setting `NO_COLOR`.

**New here?** [`docs/user-guide.md`](docs/user-guide.md) walks every step from
installing the module to confirming the change, with troubleshooting.

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
- Write any file unless you ask it to. Output goes to the console; `-CsvPath` is
  the only thing that creates a file.

If `Policy.ReadWrite.AuthenticationMethod` is missing it stops before changing
anything and prints the command needed to reconnect.

## Known limitations

**The PATCH shape is verified against one tenant, not many.** `optOutSettings`
is absent from Microsoft's published Graph metadata, so there is no schema to
validate against — the request body comes from observed behaviour, not
documentation. It worked there, and the policy's own `lastModifiedDateTime`
advanced to confirm it. That is the strongest evidence available, but it is a
sample of one. Microsoft could also change the property at any time, since an
unmodelled beta property carries no compatibility guarantee.

This is why verification is mandatory rather than optional. If the shape is
wrong or changes, you get a terminating error naming the problem — never a false
success, and never a silent no-op. Nothing else in your tenant is touched either
way.

**If verification fails for you**, run `.\Test-EntraPasskeyOptOutShape.ps1` to
see what your tenant actually returns, and please
[open an issue](https://github.com/anthonyjohnsonga/entra-passkey-dynamic-migration/issues)
with that output. That is the only way this limitation gets narrowed.

<details>
<summary><strong>Why re-reading the value is the only way to know</strong></summary>

<br>

`optOutSettings` does not appear in Microsoft's published Graph metadata. It is
returned by a plain `GET`, but `?$select=optOutSettings` fails with
`BadRequest` — the property is served without being part of Graph's queryable
model.

OData services can silently ignore properties they do not model, returning
success without changing anything, so a `200` response does not prove the write
landed. Re-reading the value is the only way to know, and it turns a silent
no-op into a clear error.

</details>

## Requirements

<details>
<summary>PowerShell 5.1+, one module, one required scope, and a qualifying admin role</summary>

<br>

| | |
|---|---|
| PowerShell | Windows PowerShell 5.1 or later |
| Module | `Microsoft.Graph.Authentication` (the full Graph SDK is not needed) |
| Required scope | `Policy.ReadWrite.AuthenticationMethod` |
| Optional scope | `GroupMember.Read.All`, or any broader directory read scope, to resolve group names |
| Role | An administrator role that can read and write the Authentication Methods policy, such as Authentication Policy Administrator |

A granted scope is not sufficient on its own — without a qualifying directory
role the request returns `403` even with consent in place.

</details>

## What is in the repo

<details>
<summary>Two scripts and three guides</summary>

<br>

| File | Purpose |
|---|---|
| `Set-EntraPasskeyDynamicMigrationOptOut.ps1` | The report and the opt-out. Supports `-ReportOnly`, `-CsvPath`, `-NoColor` and `-Verbose`. |
| `Test-EntraPasskeyOptOutShape.ps1` | Read-only probe. Issues three GETs and nothing else; reports how your tenant returns `optOutSettings`. |
| [`docs/user-guide.md`](docs/user-guide.md) | **Start here.** Every step from installing the module to confirming the change, plus troubleshooting. |
| [`docs/probe-guide.md`](docs/probe-guide.md) | Optional diagnostic: running the probe and reading its output. |
| [`docs/design-notes.md`](docs/design-notes.md) | Why the script behaves as it does, its safety boundaries, and what has been verified. |

</details>

## Verified behaviour

<details>
<summary>20 mocked scenarios under Windows PowerShell 5.1, plus one production tenant</summary>

<br>

Exercised against a mocked Graph module under Windows PowerShell 5.1 across 20
scenarios, and confirmed end to end against **one** production tenant in August
2026:

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
- Rejects a `-CsvPath` whose directory does not exist before it contacts Graph,
  so a mistyped path cannot surface after the tenant has already been changed.
- Still writes the CSV when verification fails, which is when the collected
  report is most worth having.

</details>

## Licence

[MIT](LICENSE). Not affiliated with or endorsed by Microsoft. Provided as-is,
without warranty, as stated in the licence. Review the script and run it with
`-ReportOnly` against a non-production tenant before using it in production.
