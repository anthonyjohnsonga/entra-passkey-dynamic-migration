# Probe Guide

Running `Test-EntraPasskeyOptOutShape.ps1` — an optional read-only diagnostic
that reports how your tenant returns `optOutSettings` /
`passkeyDynamicMigration`.

**It issues three GET requests and nothing else.** It changes no tenant setting,
writes no files, and neither connects nor disconnects your Graph session.

> **Most people do not need this.** Running the main script with `-ReportOnly`
> is the simpler way to look before you leap. See [user-guide.md](user-guide.md).
> This probe is for confirming the underlying Graph shape when something looks
> wrong, or before running anything that writes.

---

## Why it exists

`optOutSettings` and `passkeyDynamicMigration` do not appear anywhere in
Microsoft's published Graph metadata. The property is real and works, but there
is no schema anyone can check it against.

If Microsoft changes the shape, the main script would PATCH, fail verification,
and throw — leaving you unsure whether the write landed. This probe answers the
question before anything is written.

---

## Before you start

Setup is identical to the main script: PowerShell 5.1+, the
`Microsoft.Graph.Authentication` module, and a Graph session. See
[user-guide.md](user-guide.md) steps 1 to 5.

The probe only reads, so a read-only connection is enough:

```powershell
Connect-MgGraph -Scopes "Policy.Read.AuthenticationMethod","GroupMember.Read.All" -NoWelcome
```

If you already connected with `Policy.ReadWrite.AuthenticationMethod` for the
main script, that works too — no need to reconnect.

---

## Run it

```powershell
Set-Location 'C:\path\to\entra-passkey-dynamic-migration'
& .\Test-EntraPasskeyOptOutShape.ps1
```

To capture the output as well as display it:

```powershell
& .\Test-EntraPasskeyOptOutShape.ps1 |
    Tee-Object -FilePath "$env:USERPROFILE\Desktop\passkey-probe.txt"
```

---

## Reading the output

Six sections.

### `SESSION`

Your account and granted scopes. **The tenant ID is deliberately not printed.**

### `BETA GET: top-level keys returned`

Every property name the beta policy endpoint returned. Scan for
`optOutSettings`.

### `BETA GET: optOutSettings` — the section that matters

| Result | Meaning | What the main script will do |
|---|---|---|
| Key present, value `True` | Opt-out already enabled | Report "already true", send no PATCH |
| Key present, value `False` | Opt-out is off | PATCH to true, then verify |
| Key present, value `NULL` | Never configured — normal | Treat as needing the change, PATCH, then verify |
| Key present, `passkeyDynamicMigration : KEY NOT PRESENT` | Container exists, property does not | Still PATCHes, then verifies; safe to run |
| **`optOutSettings` ABSENT** | Not returned by default | **Stop.** See the next section |

### `BETA GET with $select=optOutSettings`

Only decisive if the previous section said ABSENT. Some Graph properties are
returned only when explicitly selected.

- **`$select` returns the property** → the main script needs a change: its read
  and verification GETs must request `?$select=optOutSettings`. Without that,
  verification would fail even after a PATCH that actually worked.
- **`$select` also fails or returns nothing** → the property name or path has
  moved. Do not run the main script until the current shape has been identified.

> **Observed behaviour:** in a tenant tested in August 2026, `optOutSettings` was
> returned by the default GET while `$select=optOutSettings` failed with
> `BadRequest`. The property is served in the payload but is not part of Graph's
> queryable model, so this combination is expected rather than a fault.

A `$select failed:` line is therefore not automatically a problem — if the
section above already showed the property present, this one is redundant.

### `BETA GET: migration state and method inventory`

`policyMigrationState` plus every method configuration, its state, its Graph
type, and whether it carried an `includeTargets` collection.

Only `migrationComplete` means legacy MFA and SSPR settings are being ignored.

### `v1.0 GET: does it return the same methods?`

Compares the v1.0 method list against beta. Beta returns strictly more —
typically hardware OATH, external authentication methods, and passkey profile
details that v1.0 omits. This is why the main script sources its report from
beta; see [design-notes.md](design-notes.md).

---

## Sharing the output

If you pass this output to someone else — a colleague, a vendor, or an issue
report — be aware of what it contains. Group display names never appear, but
your **signed-in account** and the full **method configuration** do. The tenant
ID is deliberately never printed. Redact anything you would rather not disclose;
the remaining sections still make sense with gaps in them.

---

## Next steps

Once the shape is confirmed, continue from
[user-guide.md](user-guide.md) step 6.

Troubleshooting for both scripts is in
[user-guide.md](user-guide.md#10-troubleshooting).
