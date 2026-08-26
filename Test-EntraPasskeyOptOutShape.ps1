#Requires -Version 5.1

<#
.SYNOPSIS
    Read-only probe of the beta Authentication Methods policy.

.DESCRIPTION
    Reports how this tenant actually returns optOutSettings /
    passkeyDynamicMigration, which is the one part of
    Set-EntraPasskeyDynamicMigrationOptOut.ps1 that cannot be verified offline
    because the property is absent from published Graph metadata.

    This script only ever issues GET requests. It changes nothing, and it
    neither connects nor disconnects the Graph session.

    Connect first:

        Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod","GroupMember.Read.All" -NoWelcome
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$betaUri = 'https://graph.microsoft.com/beta/policies/authenticationmethodspolicy'
$v1Uri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'

function Write-Head {
    param([string] $Text)
    Write-Host ''
    Write-Host ('--- ' + $Text + ' ---') -ForegroundColor Cyan
}

function Test-Key {
    param($Bag, [string] $Name)
    if ($null -eq $Bag) { return $false }
    if ($Bag -is [System.Collections.IDictionary]) { return $Bag.Contains($Name) }
    return ($null -ne $Bag.PSObject.Properties[$Name])
}

function Get-Key {
    param($Bag, [string] $Name)
    if (-not (Test-Key -Bag $Bag -Name $Name)) { return $null }
    if ($Bag -is [System.Collections.IDictionary]) { return $Bag[$Name] }
    return $Bag.PSObject.Properties[$Name].Value
}

$context = Get-MgContext
if ($null -eq $context) {
    throw 'No active Microsoft Graph connection. Run Connect-MgGraph first.'
}

Write-Head 'SESSION'
Write-Host ("Account       : " + $context.Account)
Write-Host ("Scopes        : " + (@($context.Scopes) -join ', '))
Write-Host 'Tenant ID intentionally not printed. Redact anything else you would rather not share.'

# ---------------------------------------------------------------- beta policy
Write-Head 'BETA GET: top-level keys returned'
$beta = Invoke-MgGraphRequest -Method GET -Uri $betaUri
if ($beta -is [System.Collections.IDictionary]) {
    $beta.Keys | Sort-Object | ForEach-Object { Write-Host ('  ' + $_) }
}
else {
    $beta.PSObject.Properties.Name | Sort-Object | ForEach-Object { Write-Host ('  ' + $_) }
}

Write-Head 'BETA GET: optOutSettings'
if (Test-Key -Bag $beta -Name 'optOutSettings') {
    $optOut = Get-Key -Bag $beta -Name 'optOutSettings'
    if ($null -eq $optOut) {
        Write-Host '  Key PRESENT, value is NULL' -ForegroundColor Yellow
    }
    else {
        Write-Host ('  Key PRESENT, .NET type: ' + $optOut.GetType().Name) -ForegroundColor Green
        Write-Host '  Contents:'
        ($optOut | ConvertTo-Json -Depth 5) -split "`n" | ForEach-Object { Write-Host ('    ' + $_) }

        if (Test-Key -Bag $optOut -Name 'passkeyDynamicMigration') {
            $value = Get-Key -Bag $optOut -Name 'passkeyDynamicMigration'
            if ($null -eq $value) {
                Write-Host '  passkeyDynamicMigration : present, NULL' -ForegroundColor Yellow
            }
            else {
                Write-Host ("  passkeyDynamicMigration : " + $value + "  (type " + $value.GetType().Name + ")") -ForegroundColor Green
            }
        }
        else {
            Write-Host '  passkeyDynamicMigration : KEY NOT PRESENT' -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host '  optOutSettings is ABSENT from the default beta GET response.' -ForegroundColor Yellow
}

# The property may be select-only rather than returned by default.
Write-Head 'BETA GET with $select=optOutSettings'
try {
    $selected = Invoke-MgGraphRequest -Method GET -Uri ($betaUri + '?$select=optOutSettings')
    ($selected | ConvertTo-Json -Depth 5) -split "`n" | ForEach-Object { Write-Host ('  ' + $_) }
}
catch {
    Write-Host ('  $select failed: ' + $_.Exception.Message) -ForegroundColor Yellow
}

# ------------------------------------------------------------ shape sanity
Write-Head 'BETA GET: migration state and method inventory'
if (Test-Key -Bag $beta -Name 'policyMigrationState') {
    Write-Host ('  policyMigrationState : ' + (Get-Key -Bag $beta -Name 'policyMigrationState'))
}
else {
    Write-Host '  policyMigrationState : KEY NOT PRESENT'
}

$methods = @(Get-Key -Bag $beta -Name 'authenticationMethodConfigurations')
Write-Host ('  method configurations returned: ' + $methods.Count)
foreach ($method in $methods) {
    $id = Get-Key -Bag $method -Name 'id'
    $state = Get-Key -Bag $method -Name 'state'
    $odata = Get-Key -Bag $method -Name '@odata.type'
    $hasInclude = Test-Key -Bag $method -Name 'includeTargets'
    Write-Host ('    {0,-26} state={1,-9} includeTargets={2}  {3}' -f $id, $state, $hasInclude, $odata)
}

# Confirms whether sourcing the report from beta actually gains anything here.
Write-Head 'v1.0 GET: does it return the same methods?'
try {
    $v1 = Invoke-MgGraphRequest -Method GET -Uri $v1Uri
    $v1Methods = @(Get-Key -Bag $v1 -Name 'authenticationMethodConfigurations')
    Write-Host ('  v1.0 method configurations returned: ' + $v1Methods.Count)
    foreach ($method in $v1Methods) {
        Write-Host ('    ' + (Get-Key -Bag $method -Name 'id'))
    }
}
catch {
    Write-Host ('  v1.0 GET failed: ' + $_.Exception.Message) -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Done. Nothing was changed. The Graph session is still connected.' -ForegroundColor Green
