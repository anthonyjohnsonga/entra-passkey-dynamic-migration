# User Guide

Running `Set-EntraPasskeyDynamicMigrationOptOut.ps1` from start to finish.

This walks through every step: installing the module, granting permissions,
connecting to Microsoft Graph, previewing the report, applying the opt-out, and
confirming it worked.

> **This script writes to your tenant.** It sets
> `optOutSettings.passkeyDynamicMigration` to `true` when the current value is
> `false` or `null`. That is the only setting it changes. Step 5 shows you the
> whole report without changing anything, and you can stop there.

**Contents**

1. [Check your PowerShell version](#1-check-your-powershell-version)
2. [Install the module](#2-install-the-module)
3. [Permissions and roles](#3-permissions-and-roles)
4. [Get the scripts](#4-get-the-scripts)
5. [Connect to Microsoft Graph](#5-connect-to-microsoft-graph)
6. [Preview the report, change nothing](#6-preview-the-report-change-nothing)
7. [Apply the opt-out](#7-apply-the-opt-out)
8. [Confirm it worked](#8-confirm-it-worked)
9. [Disconnect](#9-disconnect)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Check your PowerShell version

The script targets **Windows PowerShell 5.1** and also runs on PowerShell 7.

```powershell
$PSVersionTable.PSVersion
```

Anything `5.1` or higher is fine. Windows 10 and 11 ship with 5.1, so on a
typical admin workstation there is nothing to install.

---

## 2. Install the module

Only **`Microsoft.Graph.Authentication`** is required. The full Microsoft Graph
SDK is several hundred megabytes and is not needed — these scripts call
`Invoke-MgGraphRequest` directly.

Check whether you already have it:

```powershell
Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
    Select-Object Name, Version
```

If nothing is returned, install it for your user only:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

If you are prompted to trust the PSGallery repository, answer yes. `-Scope
CurrentUser` avoids needing an elevated prompt.

Already have the full `Microsoft.Graph` SDK installed? That works too —
`Microsoft.Graph.Authentication` is part of it.

---

## 3. Permissions and roles

Two separate things must both be true: your session needs the right **scopes**,
and your account needs a qualifying **directory role**.

### Scopes

| Scope | Needed for | If missing |
|---|---|---|
| `Policy.ReadWrite.AuthenticationMethod` | Reading the policy and setting the opt-out | The script stops before changing anything and prints the reconnect command |
| `GroupMember.Read.All` | Turning group GUIDs into readable names | The report continues, showing raw GUIDs instead of names |

The second one is optional. Any broader directory read scope — `Group.Read.All`,
`Directory.Read.All` — works just as well.

### Directory role

| Role | Can preview the report | Can apply the opt-out |
|---|---|---|
| Global Administrator | Yes | Yes |
| Authentication Policy Administrator | Yes | Yes |
| Global Reader | Yes | No — read-only |

**A granted scope is not sufficient on its own.** If your account holds no
qualifying role, Graph returns `403 Forbidden` even with consent fully in place.
This trips people up, because the consent prompt succeeds and the failure only
appears later.

Consenting to `Policy.ReadWrite.AuthenticationMethod` requires an administrator.
If you are not one, an admin must grant consent for the **Microsoft Graph
Command Line Tools** application in your tenant.

---

## 4. Get the scripts

Clone the repository:

```powershell
git clone https://github.com/anthonyjohnsonga/entra-passkey-dynamic-migration.git
Set-Location .\entra-passkey-dynamic-migration
```

Or download the ZIP from GitHub and extract it. **If you downloaded it**,
Windows marks the files as coming from the internet and PowerShell will refuse
to run them. Clear that:

```powershell
Get-ChildItem -Filter *.ps1 | Unblock-File
```

If script execution is blocked entirely, allow it for this session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

That lapses when you close the window and changes nothing permanently.

---

## 5. Connect to Microsoft Graph

The script **never connects or disconnects on your behalf** — deliberately, so a
failed run never costs you your session. You connect first:

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod","GroupMember.Read.All" -NoWelcome
```

A browser window opens for sign-in. On first use you will see a consent prompt
listing the permissions above.

### Verify the session before continuing

```powershell
Get-MgContext | Select-Object Account, TenantId, Scopes
```

Check that **the account and tenant are the ones you intend**. The script acts
on whatever tenant you are connected to — it takes no tenant ID parameter — so
this is your opportunity to catch a wrong-tenant mistake before anything is
written.

### Prefer to hold no write capability yet?

Connect read-only to preview the report:

```powershell
Connect-MgGraph -Scopes "Policy.Read.AuthenticationMethod","GroupMember.Read.All" -NoWelcome
```

Step 6 works with this. You will need to reconnect with
`Policy.ReadWrite.AuthenticationMethod` before step 7, and the script will stop
with a clear message if you forget.

---

## 6. Preview the report, change nothing

Always do this first.

```powershell
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly
```

`-ReportOnly` produces the complete report and stops before the write. No PATCH
is sent and nothing is verified.

To keep a copy:

```powershell
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly |
    Tee-Object -FilePath "$env:USERPROFILE\Desktop\auth-methods-report.txt"
```

Add `-Verbose` for per-group resolution detail.

### What you will see

**`CONNECTED TENANT`** — the account and tenant ID, and whether group name
resolution is available.

**`AUTHENTICATION POLICY STATUS`** — the migration state. Only
`migrationComplete` means legacy MFA and SSPR settings are being ignored:

```text
  Migration state:                migrationComplete
  Interpretation:                 Migration Complete - modern Authentication Methods policy is authoritative.
```

Anything else prints a prominent warning and the report continues. A `null`
state is reported as **Not Confirmed** and never assumed to mean migration
finished.

**`AUTHENTICATION METHODS`** — every method the tenant returns, including
disabled ones, with state *and* targeting together:

```text
  Passkey (FIDO2)
    Graph ID:                       Fido2
    State:                          enabled
    Included targets:               All users [passkey profiles: <guid>]
                                    Example Group [passkey profiles: <guid>]
    Excluded targets:               (none)
    Attestation enforced:           false
    Key restrictions enforced:      true
```

State alone does not tell you who can use a method, which is why targeting is
always shown beside it. Some settings live on individual targets rather than on
the method, and appear in `[square brackets]` next to each one.

Methods the script does not recognise still appear, with their Graph ID and
type. It will not fail on a method Microsoft adds later.

**`ADDITIONAL POLICY SETTINGS`** — policy version, last modified time,
registration campaign, system-preferred MFA, suspicious activity reporting. All
read-only.

**`OBSERVATIONS`** — descriptive notes, not compliance findings. Enabling an
authentication method does not by itself require MFA; Conditional Access,
Security Defaults and per-user MFA determine that, and none are visible here.

**`PASSKEY DYNAMIC MIGRATION`** — the current value and what a real run would do:

```text
  Current value:                  null
  Current value is null. A normal run would set passkeyDynamicMigration to true.

REPORT ONLY - NO CHANGES MADE
-----------------------------
  -ReportOnly was specified, so no PATCH was sent and no value was verified.
```

A `-ReportOnly` run **always** ends with that block and never prints
`FINAL VERIFIED STATUS`.

---

## 7. Apply the opt-out

When you are happy with the report:

```powershell
.\Set-EntraPasskeyDynamicMigrationOptOut.ps1
```

The report runs again, then the script acts on the current value:

| Current value | What happens |
|---|---|
| `null` or missing | PATCH to `true`, then verify |
| `false` | PATCH to `true`, then verify |
| `true` | **No PATCH sent.** Verifies and reports no change was required |

Either way it re-reads the policy afterwards and confirms the result.

---

## 8. Confirm it worked

A successful run ends with exactly this:

```text
PASSKEY DYNAMIC MIGRATION
-------------------------
  Current value:                  null
  Current value is null. Setting passkeyDynamicMigration to true...
  Update request sent.
  Verified against the policy after the operation.

FINAL VERIFIED STATUS
---------------------
{
  "passkeyDynamicMigration": true
}
```

**`FINAL VERIFIED STATUS` is your proof.** It is printed only after the value has
been re-read from Graph and confirmed to be `true`. If you do not see it,
nothing was written.

If verification fails you get a terminating error instead:

```text
Verification failed: passkeyDynamicMigration is not true after the operation.
```

That means the PATCH was accepted but the value did not change. Nothing is
ambiguous — you will never get a false success. See
[design-notes.md](design-notes.md) for why this check exists.

### Running it again is safe

The script is idempotent. A second run reports:

```text
  Current value:                  true
  passkeyDynamicMigration is already true. No change was required.
```

No PATCH is sent. You can re-run it any time to re-read the policy.

As an independent check, `Last modified` under `ADDITIONAL POLICY SETTINGS` will
show the time of your change — Graph's own record, separate from the script's
verification.

---

## 9. Disconnect

The script leaves your session connected on purpose. Close it yourself when
finished:

```powershell
Disconnect-MgGraph
```

---

## 10. Troubleshooting

**`No active Microsoft Graph connection was found.`**
Step 5 was skipped or the session expired. Reconnect.

**`The current Graph connection does not include the required scope`**
You connected without `Policy.ReadWrite.AuthenticationMethod` — likely with the
read-only alternative from step 5. The message includes the exact reconnect
command. Nothing was changed.

**`running scripts is disabled on this system`**
Execution policy. See step 4.

**The file is blocked because it came from the internet**
Run `Unblock-File` as shown in step 4.

**`403 Forbidden`**
The scope is consented but your account lacks a qualifying directory role. See
step 3 — this is the most common surprise, because consent succeeds and the
failure appears afterwards.

**`Need admin approval`, or consent cannot be completed**
`Policy.ReadWrite.AuthenticationMethod` requires administrator consent. Sign in
as an administrator, or have one grant consent for the Microsoft Graph Command
Line Tools application.

**Groups show as `Unresolved group (<guid>)`**
The group was deleted, is inaccessible, or you connected without a group-read
scope. Harmless — group names are a convenience and never block the opt-out.

**Groups show as `Group lookup throttled (<guid>)`**
Graph rate-limited the lookups. Those groups still exist. Re-run later to see
their names; the opt-out itself is unaffected.

**`Install-Module` fails or warns about an untrusted repository**
Accept the PSGallery prompt, or use `-Scope CurrentUser` as in step 2.

---

## Optional: verify the Graph shape first

If you want to confirm how your tenant returns `optOutSettings` before running
anything that writes, there is a read-only probe that issues three GETs and
nothing else. See [probe-guide.md](probe-guide.md).

Most people do not need it — `-ReportOnly` in step 6 is the simpler way to look
before you leap.
