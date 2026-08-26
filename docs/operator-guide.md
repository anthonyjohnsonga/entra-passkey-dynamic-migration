# Running `Test-EntraPasskeyOptOutShape.ps1`

A read-only probe that reports how your tenant actually returns
`optOutSettings` / `passkeyDynamicMigration`.

**It issues three GET requests and nothing else.** It changes no tenant setting,
writes no files, and neither connects nor disconnects your Graph session.

## Why run it first

`Set-EntraPasskeyDynamicMigrationOptOut.ps1` was tested offline against 16 scenarios,
but one thing cannot be verified without a real tenant: `optOutSettings` and
`passkeyDynamicMigration` do not appear anywhere in Microsoft's published Graph
metadata. The PATCH body is taken from the original script and the Microsoft
"passkeys by default" documentation, not from a schema anyone can check.

If that shape is wrong, the main script will PATCH, fail verification, and throw
— leaving you unsure whether the write landed. This probe answers the question
before anything is written.

---

## 1. Prerequisites

**PowerShell 5.1 or later.** Both scripts target Windows PowerShell 5.1 and also
run on PowerShell 7.

**The `Microsoft.Graph.Authentication` module.** Only this one module is needed
— not the full Microsoft Graph SDK. Both scripts use `Invoke-MgGraphRequest`
directly, so the several hundred megabytes of the full SDK are unnecessary.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

**A directory role that can read the Authentication Methods policy.** Consenting
to `Policy.ReadWrite.AuthenticationMethod` requires an administrator. Typically:

| Role | Can run the probe | Can run the main script |
|---|---|---|
| Global Administrator | Yes | Yes |
| Authentication Policy Administrator | Yes | Yes |
| Global Reader | Yes | No — read-only |

A granted scope is not sufficient on its own. If your account holds no
qualifying role, the GET returns `403 Forbidden` even with consent in place.

---

## 2. Connect to Graph

Run this in your PowerShell session. A browser window opens for sign-in.

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod","GroupMember.Read.All" -NoWelcome
```

These are the same scopes the main script needs, so connecting once covers both
scripts and you will not have to reconnect between them.

### Cautious alternative: read-only first

If you would rather hold no write capability until you have seen the probe
output, connect read-only instead:

```powershell
Connect-MgGraph -Scopes "Policy.Read.AuthenticationMethod","GroupMember.Read.All" -NoWelcome
```

The probe works fine with this. You will need to reconnect with
`Policy.ReadWrite.AuthenticationMethod` before running the main script — and the
main script will stop with a clear message if you forget.

### Verify the session

```powershell
Get-MgContext | Select-Object Account, TenantId, Scopes
```

Confirm the account and tenant are the ones you intend before continuing.

---

## 3. Run the probe

The scripts live in the repository root. Change to it, then run the probe:

```powershell
Set-Location 'C:\path\to\entra-passkey-dynamic-migration'
& .\Test-EntraPasskeyOptOutShape.ps1
```

To capture the output to a file as well as the screen:

```powershell
& .\Test-EntraPasskeyOptOutShape.ps1 |
    Tee-Object -FilePath "$env:USERPROFILE\Desktop\passkey-probe.txt"
```

---

## 4. Reading the output

The probe prints six sections.

### `SESSION`

Your account and granted scopes. **The tenant ID is deliberately not printed.**

### `BETA GET: top-level keys returned`

Every property name the beta policy endpoint returned. Scan for
`optOutSettings`. If it is missing here, the next section explains what follows.

### `BETA GET: optOutSettings` — the section that matters

| Result | Meaning | Action |
|---|---|---|
| Key present, `passkeyDynamicMigration` shown as `True` | Opt-out is already enabled | Main script will report "already true" and send no PATCH |
| Key present, `passkeyDynamicMigration` shown as `False` | Opt-out is off | Main script will PATCH it to true |
| Key present, value `NULL` | Never configured — normal | Main script treats null as "needs setting" and PATCHes |
| Key present, `passkeyDynamicMigration : KEY NOT PRESENT` | Container exists, property does not | Main script still PATCHes, then verifies; safe to run |
| **`optOutSettings` ABSENT** from the default GET | Property is not returned by default | **Stop.** See below |

### `BETA GET with $select=optOutSettings`

Only decisive if the previous section said ABSENT. Some Graph properties are
returned only when explicitly selected.

- **`$select` returns the property** → the main script needs a small change: its
  read and verification GETs must request `?$select=optOutSettings`. Without
  that, verification would fail even after a PATCH that actually worked.
- **`$select` also fails or returns nothing** → the property name or path has
  moved. Do not run the main script until the current shape has been identified.

A `$select failed:` line is not automatically a problem — if the section above
already showed the property present, this one is redundant.

> **Observed behaviour:** in a tenant tested in August 2026, `optOutSettings` was
> returned by the default GET while `$select=optOutSettings` failed with
> `BadRequest`. The property is served in the payload but is not part of Graph's
> queryable model, so this combination is expected rather than a fault.

### `BETA GET: migration state and method inventory`

`policyMigrationState` plus every method configuration, its state, its Graph
type, and whether it carried an `includeTargets` collection. This confirms the
main script's report will render your real data correctly.

Only `migrationComplete` means legacy MFA and SSPR settings are being ignored.

### `v1.0 GET: does it return the same methods?`

Compares the v1.0 method list against beta. This shows concretely what sourcing
the report from beta gained in *your* tenant — typically hardware OATH, external
authentication methods, and passkey profile details that v1.0 omits.

---

## 5. Sharing the output

If you pass this output to someone else — a colleague, a vendor, or an issue
report — be aware of what it contains. Group display names never appear, but
your **signed-in account** and the full **method configuration** do. The tenant
ID is deliberately never printed. Redact anything you would rather not disclose;
the remaining sections still make sense with gaps in them.

---

## 6. Troubleshooting

**`No active Microsoft Graph connection. Run Connect-MgGraph first.`**
Step 2 was skipped, or the session expired. Reconnect.

**`running scripts is disabled on this system`**
Execution policy is blocking it. Allow scripts for this session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This lapses when you close the window and changes nothing permanently.

**The file is blocked because it came from the internet**
Windows marks downloaded files. Clear it:

```powershell
Unblock-File .\Test-EntraPasskeyOptOutShape.ps1
```

**`403 Forbidden` on the GET**
The scope is consented but your account lacks a qualifying directory role. See
the role table in section 1.

**`Need admin approval` / consent prompt cannot be completed**
`Policy.ReadWrite.AuthenticationMethod` requires administrator consent. Either
sign in as an administrator or have one grant consent for the Microsoft Graph
Command Line Tools application.

**`Install-Module` fails or prompts about an untrusted repository**
Accept the PSGallery prompt, or install for your user only with
`-Scope CurrentUser` as shown above.

---

## 7. When you are finished

Neither script disconnects for you — that is deliberate, so a failed run never
costs you your session. Disconnect when you are done:

```powershell
Disconnect-MgGraph
```

---

## 8. What happens next

Once the probe output confirms the shape, run the main script:

```powershell
& .\Set-EntraPasskeyDynamicMigrationOptOut.ps1
```

That sets `passkeyDynamicMigration` to `true` unless it is already `true`. It is
the only tenant change; everything else is reported read-only.

### Seeing the report without changing anything

To review the full report first, use `-ReportOnly`:

```powershell
& .\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly
```

This runs every report section, shows what a normal run *would* do to
`passkeyDynamicMigration`, then stops before the PATCH. It sends no write
request and verifies nothing, so it deliberately ends with
`REPORT ONLY - NO CHANGES MADE` rather than a `FINAL VERIFIED STATUS` block.

Seeing that final block is therefore your proof that a real change was applied
and verified. Its absence means nothing was written.

Add `-Verbose` to either script to see per-group resolution detail, including
which throttling-detection path fired if Graph rate-limits the group lookups.
