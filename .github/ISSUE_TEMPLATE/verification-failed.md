---
name: Verification failed
about: The script reported "Verification failed: passkeyDynamicMigration is not true after the operation"
title: 'Verification failed: '
labels: verification
---

Thanks for reporting this. `optOutSettings` is absent from Microsoft's published
Graph metadata, so its shape cannot be validated in advance — reports like this
are the only way the script learns about tenants where it differs.

**Nothing else in your tenant was modified.** The script stops at the failed
verification.

## Probe output

Please run the read-only probe and paste the output. It issues three GET
requests and changes nothing:

```powershell
.\Test-EntraPasskeyOptOutShape.ps1
```

The probe does not print your tenant ID. It does print your signed-in account
and your full method configuration — redact anything you would rather not share,
the report still makes sense with gaps in it.

<details>
<summary>Probe output</summary>

```text
paste here
```

</details>

## Environment

- PowerShell version (`$PSVersionTable.PSVersion`):
- `Microsoft.Graph.Authentication` version (`Get-Module -ListAvailable Microsoft.Graph.Authentication | Select-Object Version`):
- Scopes used to connect:

## Anything else

Did the run reach `FINAL VERIFIED STATUS`, or stop before it? Anything unusual
about the tenant — sovereign cloud, recently migrated policy, and so on?
