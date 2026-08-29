#Requires -Version 5.1

<#
.SYNOPSIS
    Reports the Microsoft Entra Authentication Methods policy and enables the
    passkey dynamic migration opt-out.

.DESCRIPTION
    Uses an existing Microsoft Graph session to report the tenant's modern
    Authentication Methods policy, then checks passkeyDynamicMigration and sets
    it to true only when the current value is false or null. The value is
    re-read and verified afterwards.

    passkeyDynamicMigration is the only tenant setting this script modifies.
    Every other setting is reported read-only.

    The script never connects to or disconnects from Microsoft Graph. It writes
    no files unless -CsvPath is supplied, which is the only way to make it
    write one.

.PARAMETER ReportOnly
    Produce the full report and stop immediately before the PATCH. Nothing is
    changed and nothing is verified, so the run deliberately ends without a
    FINAL VERIFIED STATUS block. Use this to review the policy before
    authorising the opt-out.

.PARAMETER NoColor
    Write the report without console colour. The [ OK ] and [WARN] status tags
    still mark every outcome, so nothing is lost. Setting the NO_COLOR
    environment variable to any non-empty value has the same effect.

.PARAMETER CsvPath
    Also write the report to a CSV file at this path. The console report is
    unchanged; the file is written in addition to it.

    The file has one row per reported setting, with the columns Section, Item,
    Setting and Value. That shape holds the whole report, including the
    settings that do not fit a fixed set of columns, and it diffs cleanly
    between two runs or two tenants.

    The parent directory must already exist. It is checked before the script
    contacts Microsoft Graph, so a mistyped path fails immediately rather than
    after the policy has been read or changed. An existing file is overwritten.

.EXAMPLE
    .\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly

    Reports the policy and shows what a normal run would do, changing nothing.

.EXAMPLE
    .\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly -CsvPath .\tenant.csv

    Reports the policy, changes nothing, and writes the whole report to
    tenant.csv. Running this against two tenants and comparing the two files
    shows exactly where their authentication policies differ.

.EXAMPLE
    .\Set-EntraPasskeyDynamicMigrationOptOut.ps1 -ReportOnly -NoColor 6>&1 |
        Tee-Object -FilePath .\policy-report.txt

    Reports the policy without colour, which suits a log file or a build agent.

    The report is written with Write-Host, so it travels on the information
    stream. The 6>&1 redirection is what puts it in the pipeline; without it
    Tee-Object receives nothing and writes an empty file.

.EXAMPLE
    .\Set-EntraPasskeyDynamicMigrationOptOut.ps1

    Reports the policy and sets passkeyDynamicMigration to true if it is not
    already true, then verifies the result.

.NOTES
    Connect before running:

        Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod","GroupMember.Read.All" -NoWelcome

    Disconnect manually when finished:

        Disconnect-MgGraph

    This file is intentionally ASCII-only so it behaves the same under Windows
    PowerShell 5.1 regardless of how the file is saved.
#>

[CmdletBinding()]
param(
    # Produce the full report and stop before the PATCH. Nothing is changed and
    # nothing is verified, so the run ends without a FINAL VERIFIED STATUS block.
    [switch] $ReportOnly,

    # Suppress console colour. The status tags still carry every outcome.
    [switch] $NoColor,

    # Also write the report to this CSV file. One row per reported setting.
    # The console report is unchanged.
    [string] $CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Constants and script state

# The beta endpoint is the only place passkeyDynamicMigration is exposed, and it
# also returns the richer method details (passkey profiles, hardware OATH and
# external methods) that v1.0 omits, so it serves as the single policy source.
$script:BetaPolicyUri = 'https://graph.microsoft.com/beta/policies/authenticationmethodspolicy'
$script:GroupUriFormat = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=id,displayName'

$script:RequiredScope = 'Policy.ReadWrite.AuthenticationMethod'

# Any one of these permits reading a group's displayName. Testing only for
# GroupMember.Read.All would warn incorrectly when the operator connected with
# a broader directory scope.
$script:GroupReadScopes = @(
    'GroupMember.Read.All'
    'GroupMember.ReadWrite.All'
    'Group.Read.All'
    'Group.ReadWrite.All'
    'Directory.Read.All'
    'Directory.ReadWrite.All'
)

$script:AllUsersTargetId = 'all_users'
$script:NoneTargetId = '00000000-0000-0000-0000-000000000000'

# A throttled group lookup is retried once, honouring Retry-After, so a
# transient 429 does not mislabel a live group as unresolved. The wait is capped
# and the retry is abandoned for the rest of the run once it proves useless, so a
# heavily throttled tenant cannot stall the opt-out.
$script:MaxThrottleWaitSeconds = 20
$script:DefaultThrottleWaitSeconds = 5

# The CSV is assembled as the report is written rather than by walking the
# policy a second time, so the file cannot drift out of step with what the
# operator saw on screen. Section and Item track where the renderer currently
# is, which is what turns a flat sequence of fields into locatable rows.
$script:ExportCsv = -not [string]::IsNullOrWhiteSpace($CsvPath)
$script:ResolvedCsvPath = ''
$script:CsvWritten = $false
$script:CsvRows = New-Object System.Collections.ArrayList
$script:CurrentSection = ''
$script:CurrentItem = ''

# Colour is reinforcement only; the status tags carry every outcome without it.
# NO_COLOR is honoured per https://no-color.org - any non-empty value disables
# colour - so this script behaves like other tools on a build agent that sets it.
$script:UseColor = -not ($NoColor -or -not [string]::IsNullOrEmpty($env:NO_COLOR))

$script:GroupNameCache = @{}
$script:CanResolveGroups = $false
$script:GroupLookupFailures = 0
$script:ThrottledGroupLookups = 0
$script:ThrottleRetryAbandoned = $false
$script:Observations = New-Object System.Collections.ArrayList

#endregion

#region Graph response accessors

function Get-GraphValue {
    <#
        Invoke-MgGraphRequest returns nested hashtables, but the same helpers
        should keep working if a caller supplies PSObjects. Both shapes are
        probed without tripping Set-StrictMode.
    #>
    [CmdletBinding()]
    param(
        $InputObject,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Get-GraphPath {
    [CmdletBinding()]
    param(
        $InputObject,
        [Parameter(Mandatory = $true)]
        [string[]] $Path
    )

    $current = $InputObject
    foreach ($segment in $Path) {
        if ($null -eq $current) {
            return $null
        }
        $current = Get-GraphValue -InputObject $current -Name $segment
    }

    return $current
}

function Get-GraphArray {
    [CmdletBinding()]
    param(
        $InputObject,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    $value = Get-GraphValue -InputObject $InputObject -Name $Name

    # The leading comma keeps the array intact on return. A bare "return @()"
    # emits zero objects, which would hand the caller $null and break .Count
    # under Set-StrictMode.
    if ($null -eq $value) {
        return , @()
    }

    return , @($value)
}

#endregion

#region CSV export

function Resolve-CsvExportPath {
    <#
        Turns -CsvPath into a full path and proves it can be written to, before
        the script contacts Graph. A mistyped path must fail while nothing has
        happened yet, not after the tenant has already been changed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    # (Get-Location).ProviderPath, not the process working directory: PowerShell
    # does not keep the two in step, so .NET would resolve a relative path
    # against a directory the operator is not standing in.
    if ([System.IO.Path]::IsPathRooted($Path)) {
        $full = [System.IO.Path]::GetFullPath($Path)
    }
    else {
        $full = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).ProviderPath $Path))
    }

    if (Test-Path -LiteralPath $full -PathType Container) {
        throw "The -CsvPath value is a directory, not a file: $full"
    }

    $directory = [System.IO.Path]::GetDirectoryName($full)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw @"
The directory for -CsvPath does not exist: $directory

Create it first, or choose a path inside a directory that already exists.
"@
    }

    return $full
}

function Add-CsvRow {
    <#
        Records one reported setting. Section and Item default to wherever the
        renderer currently is, so most callers supply only the setting and its
        value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Setting,

        [AllowEmptyString()]
        [string] $Value = '',

        [AllowEmptyString()]
        [string] $Section,

        [AllowEmptyString()]
        [string] $Item
    )

    # Statuses raised by the export itself would arrive after the file was
    # written, so stop collecting once it has been.
    if (-not $script:ExportCsv -or $script:CsvWritten) {
        return
    }

    if (-not $PSBoundParameters.ContainsKey('Section')) { $Section = $script:CurrentSection }
    if (-not $PSBoundParameters.ContainsKey('Item')) { $Item = $script:CurrentItem }

    [void]$script:CsvRows.Add([pscustomobject]@{
        Section = $Section
        Item    = $Item
        Setting = $Setting
        Value   = $Value
    })
}

function Export-PolicyCsv {
    <#
        Writes the collected rows. Called from each of the ways the run can end,
        so a -ReportOnly run and a failed verification both still produce the
        file - a failed verification is exactly when the operator needs the data
        to report the problem.

        A failure to write is reported but never rethrown. The tenant operation
        has already happened and been verified by this point, and turning a
        successful opt-out into a terminating error over a file path would
        misrepresent what took place in the tenant.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:ExportCsv -or $script:CsvWritten) {
        return
    }

    $rowCount = $script:CsvRows.Count
    $script:CsvWritten = $true

    try {
        $script:CsvRows | Export-Csv -LiteralPath $script:ResolvedCsvPath -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Status -Level Fail -Text @(
            "Could not write the CSV to $script:ResolvedCsvPath",
            $_.Exception.Message,
            'Nothing above is affected by this. Only the file was not written.'
        )
        return
    }

    Write-Status -Level Ok -Text ('Wrote {0} rows to {1}' -f $rowCount, $script:ResolvedCsvPath)
}

#endregion

#region Console output helpers

function Write-HostColor {
    <#
        The single place this script decides whether to emit colour, so
        -NoColor and NO_COLOR cannot be honoured in one part of the report and
        ignored in another.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Text,

        [string] $Color,

        [switch] $NoNewline
    )

    if ($script:UseColor -and -not [string]::IsNullOrWhiteSpace($Color)) {
        Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
    }
    else {
        Write-Host $Text -NoNewline:$NoNewline
    }
}

function Format-DisplayValue {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) {
        return '(not set)'
    }

    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return '(not set)' }
        return $Value
    }

    # Invoke-MgGraphRequest deserialises Graph date properties into [datetime].
    # Casting one to string would use the current culture and silently drop the
    # timezone, so "08/13/2026 00:27:08" would be ambiguous on both counts.
    # Graph emits UTC, so render it back as unambiguous ISO 8601 UTC.
    if ($Value -is [datetime]) {
        $utc = $Value
        if ($utc.Kind -eq [System.DateTimeKind]::Local) {
            $utc = $utc.ToUniversalTime()
        }
        return $utc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [System.Array]) {
        if ($Value.Count -eq 0) { return '(none)' }
        return ($Value -join ', ')
    }

    return [string]$Value
}

function Get-StateColor {
    <#
        Returns the colour for a policy state, so a reader can scan the states
        down the report instead of reading every one. Colour is reinforcement
        only - the state word itself is always printed.

        Any state other than enabled or disabled is deliberately left
        uncoloured. "default" is a legitimate value on several of these settings
        and means Microsoft manages it, and a state this script does not
        recognise must not be shown as though its meaning were known.
    #>
    [CmdletBinding()]
    param([string] $State)

    switch ($State) {
        'enabled'  { return 'Green' }
        'disabled' { return 'DarkGray' }
        default    { return '' }
    }
}

function Write-Section {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Title
    )

    $script:CurrentSection = $Title
    $script:CurrentItem = ''

    Write-Host ''
    Write-HostColor -Text $Title -Color Cyan
    Write-HostColor -Text ('-' * $Title.Length) -Color Cyan
}

function Write-Item {
    <#
        Writes a sub-heading within a section - one authentication method, or
        one of the additional settings groups - and records it as the Item that
        the fields below it belong to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [int] $Indent = 2
    )

    $script:CurrentItem = $Name

    Write-Host ''
    Write-Host ((' ' * $Indent) + $Name)
}

function Write-Field {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,
        $Value,
        [int] $Indent = 2,
        [string] $Color,

        # Set by callers that record their own rows, such as Write-TargetField,
        # which emits one row per target rather than a single joined row.
        [switch] $NoExport
    )

    $display = Format-DisplayValue -Value $Value
    $text = '{0}{1,-32}{2}' -f (' ' * $Indent), ($Label + ':'), $display

    Write-HostColor -Text $text -Color $Color

    if (-not $NoExport) {
        Add-CsvRow -Setting $Label -Value $display
    }
}

function Write-Note {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Text,
        [int] $Indent = 4
    )

    Write-Host ((' ' * $Indent) + $Text)
}

function Write-Status {
    <#
        Writes an outcome line as a fixed-width ASCII tag followed by its text.

        The tag carries the severity in the characters themselves, so the meaning
        survives a transcript, a redirected log and a reader who cannot
        distinguish the colours. Colour remains, but only as reinforcement.

        Every tag is the same width, so consecutive statuses align and additional
        lines of the same status hang under the first line's text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Ok', 'Warn', 'Fail', 'Info', 'Skip')]
        [string] $Level,

        # Each element is one line. Lines after the first are aligned under the
        # text of the first rather than repeating the tag.
        [Parameter(Mandatory = $true)]
        [string[]] $Text,

        [int] $Indent = 2
    )

    $tag = '[ -- ]'
    $color = 'Gray'

    switch ($Level) {
        'Ok'   { $tag = '[ OK ]'; $color = 'Green' }
        'Warn' { $tag = '[WARN]'; $color = 'Yellow' }
        'Fail' { $tag = '[FAIL]'; $color = 'Red' }
        'Skip' { $tag = '[SKIP]'; $color = 'DarkGray' }
        'Info' { $tag = '[ -- ]'; $color = 'Gray' }
    }

    $margin = ' ' * $Indent
    $hangingIndent = ' ' * ($Indent + $tag.Length + 1)

    # A status is one row whatever its length, tagged so that it can be told
    # apart from the settings when filtering the file.
    Add-CsvRow -Setting 'Status' -Value ('[{0}] {1}' -f $Level.ToUpperInvariant(), ($Text -join ' '))

    for ($i = 0; $i -lt $Text.Count; $i++) {
        if ($i -eq 0) {
            Write-HostColor -Text ($margin + $tag + ' ') -Color $color -NoNewline
            Write-Host $Text[$i]
        }
        else {
            Write-Host ($hangingIndent + $Text[$i])
        }
    }
}

function Add-Observation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Text
    )

    [void]$script:Observations.Add($Text)
}

#endregion

#region Context and policy retrieval

function Test-RequiredGraphContext {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw @'
Microsoft.Graph.Authentication is not installed.
Run the following command, then connect to Graph and rerun this script:

Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
'@
    }

    Import-Module Microsoft.Graph.Authentication

    $context = Get-MgContext
    if ($null -eq $context -or [string]::IsNullOrWhiteSpace($context.TenantId)) {
        throw @"
No active Microsoft Graph connection was found.
Connect first with:

Connect-MgGraph -Scopes "$script:RequiredScope","GroupMember.Read.All" -NoWelcome
"@
    }

    $scopes = @()
    if ($null -ne $context.Scopes) {
        $scopes = @($context.Scopes)
    }

    if ($scopes -notcontains $script:RequiredScope) {
        throw @"
The current Graph connection does not include the required scope: $script:RequiredScope
Reconnect with:

Disconnect-MgGraph
Connect-MgGraph -Scopes "$script:RequiredScope","GroupMember.Read.All" -NoWelcome
"@
    }

    $script:CanResolveGroups = $false
    foreach ($scope in $script:GroupReadScopes) {
        if ($scopes -contains $scope) {
            $script:CanResolveGroups = $true
            break
        }
    }

    return $context
}

function Get-AuthenticationMethodsPolicy {
    [CmdletBinding()]
    param()

    return Invoke-MgGraphRequest -Method GET -Uri $script:BetaPolicyUri
}

function Get-MigrationStateDisplay {
    [CmdletBinding()]
    param([string] $State)

    # Only migrationComplete confirms that legacy MFA and SSPR settings are
    # ignored. A null or unknown state is never treated as complete.
    switch ($State) {
        'migrationComplete' {
            return [pscustomobject]@{
                IsComplete = $true
                Text       = 'Migration Complete - modern Authentication Methods policy is authoritative.'
            }
        }
        'migrationInProgress' {
            return [pscustomobject]@{
                IsComplete = $false
                Text       = 'Migration In Progress - legacy MFA or SSPR settings may also apply.'
            }
        }
        'preMigration' {
            return [pscustomobject]@{
                IsComplete = $false
                Text       = 'Pre-Migration - legacy MFA or SSPR settings may also apply.'
            }
        }
        default {
            return [pscustomobject]@{
                IsComplete = $false
                Text       = 'Not Confirmed - legacy MFA or SSPR settings may also apply.'
            }
        }
    }
}

#endregion

#region Group target resolution

function Get-ThrottleRetrySeconds {
    <#
        Returns the number of seconds to wait before retrying a throttled Graph
        request, or $null when the failure was not throttling.

        Invoke-MgGraphRequest surfaces errors in more than one shape depending on
        the module version, so the status code and Retry-After header are probed
        defensively rather than assumed.
    #>
    [CmdletBinding()]
    param($ErrorRecord)

    $exception = Get-GraphValue -InputObject $ErrorRecord -Name 'Exception'
    if ($null -eq $exception) {
        return $null
    }

    $response = Get-GraphValue -InputObject $exception -Name 'Response'

    $statusValue = Get-GraphValue -InputObject $response -Name 'StatusCode'
    if ($null -eq $statusValue) {
        $statusValue = Get-GraphValue -InputObject $exception -Name 'StatusCode'
    }

    $statusCode = 0
    if ($null -ne $statusValue) {
        try {
            $statusCode = [int]$statusValue
        }
        catch {
            # HttpStatusCode can arrive as its name rather than its number.
            if ("$statusValue" -match 'TooManyRequests') {
                $statusCode = 429
            }
        }
    }

    if ($statusCode -eq 0) {
        $message = [string](Get-GraphValue -InputObject $exception -Name 'Message')
        if ($message -match '\b429\b' -or $message -match 'TooManyRequests' -or $message -match 'throttl') {
            $statusCode = 429
        }
    }

    if ($statusCode -ne 429) {
        return $null
    }

    $seconds = 0

    # HttpResponseHeaders exposes Retry-After as a parsed RetryConditionHeaderValue.
    $headers = Get-GraphValue -InputObject $response -Name 'Headers'
    $retryAfter = Get-GraphValue -InputObject $headers -Name 'RetryAfter'
    $delta = Get-GraphValue -InputObject $retryAfter -Name 'Delta'
    if ($null -ne $delta) {
        try {
            $seconds = [int]$delta.TotalSeconds
        }
        catch {
            $seconds = 0
        }
    }

    if ($seconds -le 0) {
        # Fall back to the raw header when the parsed form is unavailable.
        try {
            $rawValues = $headers.GetValues('Retry-After')
            if ($null -ne $rawValues -and @($rawValues).Count -gt 0) {
                $seconds = [int]@($rawValues)[0]
            }
        }
        catch {
            $seconds = 0
        }
    }

    if ($seconds -le 0) {
        $seconds = $script:DefaultThrottleWaitSeconds
    }

    if ($seconds -gt $script:MaxThrottleWaitSeconds) {
        $seconds = $script:MaxThrottleWaitSeconds
    }

    return $seconds
}

function Get-TargetDisplayName {
    [CmdletBinding()]
    param(
        [string] $Id,
        [string] $TargetType
    )

    if ([string]::IsNullOrWhiteSpace($Id)) {
        return '(no target id)'
    }

    if ($Id -eq $script:AllUsersTargetId) {
        return 'All users'
    }

    if ($Id -eq $script:NoneTargetId) {
        return 'None'
    }

    if ($TargetType -eq 'user') {
        return "User ($Id)"
    }

    if ($script:GroupNameCache.ContainsKey($Id)) {
        return $script:GroupNameCache[$Id]
    }

    $display = "Unresolved group ($Id)"

    if ($script:CanResolveGroups) {
        $uri = $script:GroupUriFormat -f $Id
        $attempt = 0
        $maxAttempts = 2   # the initial call plus a single retry on throttling

        while ($attempt -lt $maxAttempts) {
            $attempt++

            try {
                $group = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                $displayName = [string](Get-GraphValue -InputObject $group -Name 'displayName')

                if (-not [string]::IsNullOrWhiteSpace($displayName)) {
                    $display = $displayName
                }
                else {
                    $script:GroupLookupFailures++
                }

                break
            }
            catch {
                # A deleted group or a single denied lookup must never stop the
                # report or the opt-out.
                $retrySeconds = Get-ThrottleRetrySeconds -ErrorRecord $_

                if ($null -eq $retrySeconds) {
                    $script:GroupLookupFailures++
                    Write-Verbose "Group lookup failed for $Id : $($_.Exception.Message)"
                    break
                }

                if ($attempt -lt $maxAttempts -and -not $script:ThrottleRetryAbandoned) {
                    Write-Verbose "Throttled resolving $Id. Waiting $retrySeconds second(s) before one retry."
                    Start-Sleep -Seconds $retrySeconds
                    continue
                }

                # Throttling that survives a retry is reported separately, so a
                # live group is never presented as deleted or inaccessible.
                if ($attempt -ge $maxAttempts) {
                    # Retrying did not help, so stop paying the wait for every
                    # remaining group in this run.
                    $script:ThrottleRetryAbandoned = $true
                }

                $display = "Group lookup throttled ($Id)"
                $script:ThrottledGroupLookups++
                Write-Verbose "Group lookup throttled for $Id after $attempt attempt(s)."
                break
            }
        }
    }

    $script:GroupNameCache[$Id] = $display
    return $display
}

function Add-GroupTargetId {
    [CmdletBinding()]
    param(
        $Targets,
        [Parameter(Mandatory = $true)]
        $Collection
    )

    foreach ($target in @($Targets)) {
        if ($null -eq $target) {
            continue
        }

        $id = [string](Get-GraphValue -InputObject $target -Name 'id')
        $targetType = [string](Get-GraphValue -InputObject $target -Name 'targetType')

        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($id -eq $script:AllUsersTargetId -or $id -eq $script:NoneTargetId) { continue }
        if ($targetType -eq 'user') { continue }

        if (-not $Collection.Contains($id)) {
            [void]$Collection.Add($id)
        }
    }
}

function Resolve-PolicyGroupTargets {
    <#
        Collects every group id referenced anywhere in the policy and resolves
        each one once, so the rendering pass below is served entirely from cache.
    #>
    [CmdletBinding()]
    param($Policy)

    $groupIds = New-Object System.Collections.ArrayList

    foreach ($method in (Get-GraphArray -InputObject $Policy -Name 'authenticationMethodConfigurations')) {
        Add-GroupTargetId -Targets (Get-GraphArray -InputObject $method -Name 'includeTargets') -Collection $groupIds
        Add-GroupTargetId -Targets (Get-GraphArray -InputObject $method -Name 'excludeTargets') -Collection $groupIds

        # Microsoft Authenticator feature settings carry their own single targets.
        # This list must match the feature settings rendered by
        # Show-AuthenticationMethodDetails, so that no group is looked up for a
        # target that is never shown to the operator.
        $featureSettings = Get-GraphValue -InputObject $method -Name 'featureSettings'
        if ($null -ne $featureSettings) {
            foreach ($featureName in @('numberMatchingRequiredState', 'displayAppInformationRequiredState', 'displayLocationInformationRequiredState')) {
                $feature = Get-GraphValue -InputObject $featureSettings -Name $featureName
                if ($null -eq $feature) { continue }
                Add-GroupTargetId -Targets @(Get-GraphValue -InputObject $feature -Name 'includeTarget') -Collection $groupIds
                Add-GroupTargetId -Targets @(Get-GraphValue -InputObject $feature -Name 'excludeTarget') -Collection $groupIds
            }
        }
    }

    $campaign = Get-GraphPath -InputObject $Policy -Path 'registrationEnforcement', 'authenticationMethodsRegistrationCampaign'
    Add-GroupTargetId -Targets (Get-GraphArray -InputObject $campaign -Name 'includeTargets') -Collection $groupIds
    Add-GroupTargetId -Targets (Get-GraphArray -InputObject $campaign -Name 'excludeTargets') -Collection $groupIds

    $systemCredentials = Get-GraphValue -InputObject $Policy -Name 'systemCredentialPreferences'
    Add-GroupTargetId -Targets (Get-GraphArray -InputObject $systemCredentials -Name 'includeTargets') -Collection $groupIds
    Add-GroupTargetId -Targets (Get-GraphArray -InputObject $systemCredentials -Name 'excludeTargets') -Collection $groupIds

    $suspiciousActivity = Get-GraphValue -InputObject $Policy -Name 'reportSuspiciousActivitySettings'
    Add-GroupTargetId -Targets @(Get-GraphValue -InputObject $suspiciousActivity -Name 'includeTarget') -Collection $groupIds

    foreach ($id in $groupIds) {
        [void](Get-TargetDisplayName -Id $id -TargetType 'group')
    }
}

function Format-FeatureSetting {
    <#
        Renders an authenticationMethodFeatureConfiguration as its state plus the
        targets it applies to. The state alone would imply a feature is tenant-wide
        when it may be scoped to a single group.
    #>
    [CmdletBinding()]
    param($Feature)

    if ($null -eq $Feature) {
        return '(not set)'
    }

    $state = [string](Get-GraphValue -InputObject $Feature -Name 'state')
    if ([string]::IsNullOrWhiteSpace($state)) {
        $state = '(not set)'
    }

    $notes = New-Object System.Collections.ArrayList

    $includeTarget = Get-GraphValue -InputObject $Feature -Name 'includeTarget'
    if ($null -ne $includeTarget) {
        $includeId = [string](Get-GraphValue -InputObject $includeTarget -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($includeId)) {
            $includeType = [string](Get-GraphValue -InputObject $includeTarget -Name 'targetType')
            [void]$notes.Add('applies to: ' + (Get-TargetDisplayName -Id $includeId -TargetType $includeType))
        }
    }

    $excludeTarget = Get-GraphValue -InputObject $Feature -Name 'excludeTarget'
    if ($null -ne $excludeTarget) {
        $excludeId = [string](Get-GraphValue -InputObject $excludeTarget -Name 'id')
        # An empty exclusion is expressed as the all-zero GUID. Reporting it adds noise.
        if (-not [string]::IsNullOrWhiteSpace($excludeId) -and $excludeId -ne $script:NoneTargetId) {
            $excludeType = [string](Get-GraphValue -InputObject $excludeTarget -Name 'targetType')
            [void]$notes.Add('excluding: ' + (Get-TargetDisplayName -Id $excludeId -TargetType $excludeType))
        }
    }

    if ($notes.Count -gt 0) {
        return '{0} ({1})' -f $state, ($notes -join '; ')
    }

    return $state
}

function Format-TargetList {
    [CmdletBinding()]
    param(
        $Targets,
        [string] $MethodId = ''
    )

    $result = New-Object System.Collections.ArrayList

    foreach ($target in @($Targets)) {
        if ($null -eq $target) {
            continue
        }

        $id = [string](Get-GraphValue -InputObject $target -Name 'id')
        $targetType = [string](Get-GraphValue -InputObject $target -Name 'targetType')
        $name = Get-TargetDisplayName -Id $id -TargetType $targetType

        $notes = New-Object System.Collections.ArrayList

        if ((Get-GraphValue -InputObject $target -Name 'isRegistrationRequired') -eq $true) {
            [void]$notes.Add('registration required')
        }

        # Several settings the report must show live on the individual target
        # rather than on the method configuration itself.
        switch ($MethodId) {
            'MicrosoftAuthenticator' {
                $mode = [string](Get-GraphValue -InputObject $target -Name 'authenticationMode')
                if (-not [string]::IsNullOrWhiteSpace($mode)) {
                    [void]$notes.Add("mode: $mode")
                }
            }
            'Fido2' {
                $profiles = Get-GraphArray -InputObject $target -Name 'allowedPasskeyProfiles'
                if ($profiles.Count -gt 0) {
                    [void]$notes.Add("passkey profiles: $($profiles -join ', ')")
                }
            }
            'Sms' {
                $usableForSignIn = Get-GraphValue -InputObject $target -Name 'isUsableForSignIn'
                if ($null -ne $usableForSignIn) {
                    if ($usableForSignIn -eq $true) {
                        [void]$notes.Add('usable for sign-in')
                    }
                    else {
                        [void]$notes.Add('not usable for sign-in')
                    }
                }
            }
            'RegistrationCampaign' {
                $targetedMethod = [string](Get-GraphValue -InputObject $target -Name 'targetedAuthenticationMethod')
                if (-not [string]::IsNullOrWhiteSpace($targetedMethod)) {
                    [void]$notes.Add("method: $targetedMethod")
                }
            }
        }

        if ($notes.Count -gt 0) {
            [void]$result.Add(('{0} [{1}]' -f $name, ($notes -join '; ')))
        }
        else {
            [void]$result.Add($name)
        }
    }

    if ($result.Count -eq 0) {
        return @('(none)')
    }

    return $result.ToArray()
}

function Write-TargetField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,
        $Targets,
        [string] $MethodId = '',
        [int] $Indent = 4
    )

    $items = @(Format-TargetList -Targets $Targets -MethodId $MethodId)

    Write-Field -Label $Label -Value $items[0] -Indent $Indent -NoExport
    for ($i = 1; $i -lt $items.Count; $i++) {
        Write-Host ('{0}{1,-32}{2}' -f (' ' * $Indent), '', $items[$i])
    }

    # One row per target rather than one joined row, so that adding or removing
    # a single target shows up as a single line in a diff.
    foreach ($item in $items) {
        Add-CsvRow -Setting $Label -Value $item
    }
}

#endregion

#region Authentication method reporting

function Get-AuthenticationMethodFriendlyName {
    [CmdletBinding()]
    param($Method)

    $id = [string](Get-GraphValue -InputObject $Method -Name 'id')
    $odataType = [string](Get-GraphValue -InputObject $Method -Name '@odata.type')

    if ($odataType -match 'externalAuthenticationMethodConfiguration') {
        $displayName = [string](Get-GraphValue -InputObject $Method -Name 'displayName')
        if (-not [string]::IsNullOrWhiteSpace($displayName)) {
            return "External method: $displayName"
        }
        return "External method ($id)"
    }

    switch ($id) {
        'MicrosoftAuthenticator' { return 'Microsoft Authenticator' }
        'Fido2'                  { return 'Passkey (FIDO2)' }
        'Sms'                    { return 'SMS' }
        'Voice'                  { return 'Voice call' }
        'TemporaryAccessPass'    { return 'Temporary Access Pass' }
        'SoftwareOath'           { return 'Software OATH token' }
        'HardwareOath'           { return 'Hardware OATH token' }
        'Email'                  { return 'Email one-time passcode' }
        'X509Certificate'        { return 'Certificate-based authentication' }
        'QRCodePin'              { return 'QR code and PIN' }

        # Returned by the beta endpoint only. Confirmed present in a live tenant.
        'VerifiableCredentials'       { return 'Verifiable credentials (Verified ID)' }
        'FederatedIdentityCredential' { return 'Federated identity credential' }
        default {
            if ([string]::IsNullOrWhiteSpace($id)) {
                return 'Unrecognized method'
            }
            return "Unrecognized method ($id)"
        }
    }
}

function Show-AuthenticationMethodDetails {
    <#
        Renders the common properties for every method, then adds curated
        details for the methods that have them. Unknown methods fall through to
        the common properties and their raw Graph type, and never cause a
        failure.
    #>
    [CmdletBinding()]
    param($Method)

    $id = [string](Get-GraphValue -InputObject $Method -Name 'id')
    $odataType = [string](Get-GraphValue -InputObject $Method -Name '@odata.type')
    $state = [string](Get-GraphValue -InputObject $Method -Name 'state')

    Write-Item -Name (Get-AuthenticationMethodFriendlyName -Method $Method)

    Write-Field -Label 'Graph ID' -Value $id -Indent 4
    Write-Field -Label 'State' -Value $state -Indent 4 -Color (Get-StateColor -State $state)
    Write-TargetField -Label 'Included targets' -Targets (Get-GraphArray -InputObject $Method -Name 'includeTargets') -MethodId $id
    Write-TargetField -Label 'Excluded targets' -Targets (Get-GraphArray -InputObject $Method -Name 'excludeTargets') -MethodId $id

    if ($odataType -match 'externalAuthenticationMethodConfiguration') {
        Write-Field -Label 'Display name' -Value (Get-GraphValue -InputObject $Method -Name 'displayName') -Indent 4
        Write-Field -Label 'Application ID' -Value (Get-GraphValue -InputObject $Method -Name 'appId') -Indent 4
        return
    }

    switch ($id) {
        'MicrosoftAuthenticator' {
            $featureSettings = Get-GraphValue -InputObject $Method -Name 'featureSettings'
            Write-Field -Label 'Software OATH allowed' -Value (Get-GraphValue -InputObject $Method -Name 'isSoftwareOathEnabled') -Indent 4
            Write-Field -Label 'Number matching' -Value (Format-FeatureSetting -Feature (Get-GraphValue -InputObject $featureSettings -Name 'numberMatchingRequiredState')) -Indent 4
            Write-Field -Label 'Application information' -Value (Format-FeatureSetting -Feature (Get-GraphValue -InputObject $featureSettings -Name 'displayAppInformationRequiredState')) -Indent 4
            Write-Field -Label 'Location information' -Value (Format-FeatureSetting -Feature (Get-GraphValue -InputObject $featureSettings -Name 'displayLocationInformationRequiredState')) -Indent 4
            Write-Note 'Authentication mode is configured per included target and is shown with each target above.'
        }
        'Fido2' {
            $keyRestrictions = Get-GraphValue -InputObject $Method -Name 'keyRestrictions'
            Write-Field -Label 'Default passkey profile' -Value (Get-GraphValue -InputObject $Method -Name 'defaultPasskeyProfile') -Indent 4
            Write-Field -Label 'Self-service registration' -Value (Get-GraphValue -InputObject $Method -Name 'isSelfServiceRegistrationAllowed') -Indent 4
            Write-Field -Label 'Attestation enforced' -Value (Get-GraphValue -InputObject $Method -Name 'isAttestationEnforced') -Indent 4
            Write-Field -Label 'Key restrictions enforced' -Value (Get-GraphValue -InputObject $keyRestrictions -Name 'isEnforced') -Indent 4
            Write-Field -Label 'Key restriction type' -Value (Get-GraphValue -InputObject $keyRestrictions -Name 'enforcementType') -Indent 4
            Write-Field -Label 'Restricted key count' -Value (Get-GraphArray -InputObject $keyRestrictions -Name 'aaGuids').Count -Indent 4
            Write-Note 'Allowed passkey profiles are configured per included target and are shown with each target above.'
        }
        'Sms' {
            Write-Note 'Sign-in availability is configured per included target and is shown with each target above.'
            Write-Note 'Telecom provider: Microsoft-provided SMS is being retired. This is general guidance, not a value read from this tenant.'
        }
        'Voice' {
            Write-Field -Label 'Office phone allowed' -Value (Get-GraphValue -InputObject $Method -Name 'isOfficePhoneAllowed') -Indent 4
            Write-Note 'Telecom provider: Microsoft-provided voice calls are being retired. This is general guidance, not a value read from this tenant.'
        }
        'TemporaryAccessPass' {
            Write-Field -Label 'One-time use' -Value (Get-GraphValue -InputObject $Method -Name 'isUsableOnce') -Indent 4
            Write-Field -Label 'Default length' -Value (Get-GraphValue -InputObject $Method -Name 'defaultLength') -Indent 4
            Write-Field -Label 'Default lifetime (minutes)' -Value (Get-GraphValue -InputObject $Method -Name 'defaultLifetimeInMinutes') -Indent 4
            Write-Field -Label 'Minimum lifetime (minutes)' -Value (Get-GraphValue -InputObject $Method -Name 'minimumLifetimeInMinutes') -Indent 4
            Write-Field -Label 'Maximum lifetime (minutes)' -Value (Get-GraphValue -InputObject $Method -Name 'maximumLifetimeInMinutes') -Indent 4
        }
        'Email' {
            Write-Field -Label 'External ID may use email OTP' -Value (Get-GraphValue -InputObject $Method -Name 'allowExternalIdToUseEmailOtp') -Indent 4
        }
        'X509Certificate' {
            $modeConfiguration = Get-GraphValue -InputObject $Method -Name 'authenticationModeConfiguration'
            Write-Field -Label 'Default authentication mode' -Value (Get-GraphValue -InputObject $modeConfiguration -Name 'x509CertificateAuthenticationDefaultMode') -Indent 4
            Write-Field -Label 'Authentication mode rules' -Value (Get-GraphArray -InputObject $modeConfiguration -Name 'rules').Count -Indent 4
            Write-Field -Label 'Certificate user bindings' -Value (Get-GraphArray -InputObject $Method -Name 'certificateUserBindings').Count -Indent 4
        }
        'QRCodePin' {
            Write-Field -Label 'PIN length' -Value (Get-GraphValue -InputObject $Method -Name 'pinLength') -Indent 4
            Write-Field -Label 'QR code lifetime (days)' -Value (Get-GraphValue -InputObject $Method -Name 'standardQRCodeLifetimeInDays') -Indent 4
        }
        'FederatedIdentityCredential' {
            # Absent from published Graph metadata, so no settings can be
            # curated for it yet. Common properties above still apply.
            Write-Field -Label 'Graph type' -Value $odataType -Indent 4
            Write-Note 'Microsoft has not yet published method-specific settings for this method.'
        }
        'SoftwareOath' { }
        'HardwareOath' { }
        'VerifiableCredentials' { }
        default {
            Write-Field -Label 'Graph type' -Value $odataType -Indent 4
            Write-Note 'This method is not specifically recognized by this script. Common properties are shown above.'
        }
    }
}

function Show-AdditionalPolicySettings {
    [CmdletBinding()]
    param($Policy)

    Write-Section 'ADDITIONAL POLICY SETTINGS'

    Write-Field -Label 'Policy version' -Value (Get-GraphValue -InputObject $Policy -Name 'policyVersion')
    Write-Field -Label 'Last modified' -Value (Get-GraphValue -InputObject $Policy -Name 'lastModifiedDateTime')

    $campaign = Get-GraphPath -InputObject $Policy -Path 'registrationEnforcement', 'authenticationMethodsRegistrationCampaign'
    $campaignState = [string](Get-GraphValue -InputObject $campaign -Name 'state')
    Write-Item -Name 'Registration Campaign'
    Write-Field -Label 'State' -Value $campaignState -Indent 4 -Color (Get-StateColor -State $campaignState)
    Write-Field -Label 'Snooze duration (days)' -Value (Get-GraphValue -InputObject $campaign -Name 'snoozeDurationInDays') -Indent 4
    Write-Field -Label 'Enforce after snoozes' -Value (Get-GraphValue -InputObject $campaign -Name 'enforceRegistrationAfterAllowedSnoozes') -Indent 4
    Write-TargetField -Label 'Included targets' -Targets (Get-GraphArray -InputObject $campaign -Name 'includeTargets') -MethodId 'RegistrationCampaign'
    Write-TargetField -Label 'Excluded targets' -Targets (Get-GraphArray -InputObject $campaign -Name 'excludeTargets')

    $systemCredentials = Get-GraphValue -InputObject $Policy -Name 'systemCredentialPreferences'
    $systemCredentialsState = [string](Get-GraphValue -InputObject $systemCredentials -Name 'state')
    Write-Item -Name 'System-preferred multifactor authentication'
    Write-Field -Label 'State' -Value $systemCredentialsState -Indent 4 -Color (Get-StateColor -State $systemCredentialsState)
    Write-TargetField -Label 'Included targets' -Targets (Get-GraphArray -InputObject $systemCredentials -Name 'includeTargets')
    Write-TargetField -Label 'Excluded targets' -Targets (Get-GraphArray -InputObject $systemCredentials -Name 'excludeTargets')

    $suspiciousActivity = Get-GraphValue -InputObject $Policy -Name 'reportSuspiciousActivitySettings'
    $suspiciousActivityState = [string](Get-GraphValue -InputObject $suspiciousActivity -Name 'state')
    Write-Item -Name 'Suspicious activity reporting'
    Write-Field -Label 'State' -Value $suspiciousActivityState -Indent 4 -Color (Get-StateColor -State $suspiciousActivityState)
    Write-Field -Label 'Voice reporting code' -Value (Get-GraphValue -InputObject $suspiciousActivity -Name 'voiceReportingCode') -Indent 4
    Write-TargetField -Label 'Included target' -Targets @(Get-GraphValue -InputObject $suspiciousActivity -Name 'includeTarget')

    Write-Host ''
    Write-Note 'These settings are reported read-only. This script does not modify them.' -Indent 2
}

function Show-PolicyObservations {
    [CmdletBinding()]
    param(
        $Policy,
        $MigrationDisplay
    )

    if (-not $MigrationDisplay.IsComplete) {
        Add-Observation 'Migration to the modern Authentication Methods policy is not confirmed complete, so legacy MFA or SSPR settings may also apply.'
    }

    foreach ($method in (Get-GraphArray -InputObject $Policy -Name 'authenticationMethodConfigurations')) {
        $id = [string](Get-GraphValue -InputObject $method -Name 'id')
        $state = [string](Get-GraphValue -InputObject $method -Name 'state')

        switch ($id) {
            'Sms' {
                if ($state -eq 'enabled') {
                    Add-Observation 'SMS is enabled in the modern Authentication Methods policy.'
                }
            }
            'Voice' {
                if ($state -eq 'enabled') {
                    Add-Observation 'Voice call is enabled in the modern Authentication Methods policy.'
                }
            }
            'MicrosoftAuthenticator' {
                if ($state -ne 'enabled') {
                    Add-Observation 'Microsoft Authenticator is disabled in the modern Authentication Methods policy.'
                }
            }
            'Fido2' {
                if ($state -ne 'enabled') {
                    Add-Observation 'Passkey (FIDO2) is disabled in the modern Authentication Methods policy.'
                }
                else {
                    $targetsAllUsers = $false
                    foreach ($target in (Get-GraphArray -InputObject $method -Name 'includeTargets')) {
                        if ([string](Get-GraphValue -InputObject $target -Name 'id') -eq $script:AllUsersTargetId) {
                            $targetsAllUsers = $true
                            break
                        }
                    }

                    if (-not $targetsAllUsers) {
                        Add-Observation 'Passkey (FIDO2) is enabled but is not targeted at all users.'
                    }
                }
            }
        }
    }

    if (-not $script:CanResolveGroups) {
        Add-Observation 'Group name resolution is unavailable because no group-read scope (such as GroupMember.Read.All) is present. Group IDs are shown instead.'
    }

    if ($script:GroupLookupFailures -gt 0) {
        Add-Observation "$script:GroupLookupFailures group target(s) could not be resolved to a display name. The group may be deleted or the lookup may have been denied."
    }

    if ($script:ThrottledGroupLookups -gt 0) {
        Add-Observation "$script:ThrottledGroupLookups group target(s) could not be resolved because Microsoft Graph throttled the requests. These groups still exist. Rerun the script later to see their names."
    }

    $campaignState = [string](Get-GraphPath -InputObject $Policy -Path 'registrationEnforcement', 'authenticationMethodsRegistrationCampaign', 'state')
    if ($campaignState -eq 'enabled') {
        Add-Observation 'A Registration Campaign is already enabled. This script does not change it.'
    }

    Write-Section 'OBSERVATIONS'

    if ($script:Observations.Count -eq 0) {
        Write-Status -Level Info -Text 'No observations.'
    }
    else {
        foreach ($observation in $script:Observations) {
            Write-Host ('  - ' + $observation)
            Add-CsvRow -Setting 'Observation' -Value $observation
        }
    }

    Write-Host ''
    Write-Note 'These are descriptive observations, not compliance findings. Enabling an authentication' -Indent 2
    Write-Note 'method does not by itself require MFA. Conditional Access, Security Defaults, per-user MFA' -Indent 2
    Write-Note 'and other controls determine when MFA is required.' -Indent 2
}

#endregion

#region Passkey dynamic migration

function Get-PasskeyDynamicMigrationStatus {
    [CmdletBinding()]
    param($Policy)

    # optOutSettings can be absent, or present with a null value.
    $optOutSettings = Get-GraphValue -InputObject $Policy -Name 'optOutSettings'
    if ($null -eq $optOutSettings) {
        return $null
    }

    return Get-GraphValue -InputObject $optOutSettings -Name 'passkeyDynamicMigration'
}

function Set-PasskeyDynamicMigrationOptOut {
    [CmdletBinding()]
    param()

    $requestBody = @{
        optOutSettings = @{
            passkeyDynamicMigration = $true
        }
    } | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest `
        -Method PATCH `
        -Uri $script:BetaPolicyUri `
        -Body $requestBody `
        -ContentType 'application/json' | Out-Null
}

function Test-PasskeyDynamicMigrationStatus {
    [CmdletBinding()]
    param()

    $verifiedPolicy = Get-AuthenticationMethodsPolicy
    return ((Get-PasskeyDynamicMigrationStatus -Policy $verifiedPolicy) -eq $true)
}

#endregion

#region Main

# Prove the destination before anything is read from or written to the tenant,
# so a mistyped path costs nothing.
if ($script:ExportCsv) {
    $script:ResolvedCsvPath = Resolve-CsvExportPath -Path $CsvPath
}

$context = Test-RequiredGraphContext

Write-Section 'CONNECTED TENANT'
Write-Field -Label 'Account' -Value $context.Account
Write-Field -Label 'Tenant ID' -Value $context.TenantId
if ($script:CanResolveGroups) {
    Write-Field -Label 'Group name resolution' -Value 'Available'
}
else {
    Write-Field -Label 'Group name resolution' -Value 'Unavailable - group IDs will be shown' -Color Yellow
}

$policy = Get-AuthenticationMethodsPolicy

$migrationState = [string](Get-GraphValue -InputObject $policy -Name 'policyMigrationState')
$migrationDisplay = Get-MigrationStateDisplay -State $migrationState

Write-Section 'AUTHENTICATION POLICY STATUS'
Write-Field -Label 'Migration state' -Value $migrationState
if ($migrationDisplay.IsComplete) {
    Write-Field -Label 'Interpretation' -Value $migrationDisplay.Text -Color Green
}
else {
    Write-Field -Label 'Interpretation' -Value $migrationDisplay.Text -Color Yellow

    Write-Host ''
    Write-Status -Level Warn -Text @(
        'Migration to the modern Authentication Methods policy is not confirmed complete.'
        'Legacy MFA and SSPR authentication method settings may still apply to users.'
        'The modern policy is still reported below.'
    )
}

Resolve-PolicyGroupTargets -Policy $policy

Write-Section 'AUTHENTICATION METHODS'
$methods = Get-GraphArray -InputObject $policy -Name 'authenticationMethodConfigurations'
if ($methods.Count -eq 0) {
    Write-Status -Level Warn -Text 'No authentication method configurations were returned.'
}
else {
    foreach ($method in $methods) {
        Show-AuthenticationMethodDetails -Method $method
    }
}

Show-AdditionalPolicySettings -Policy $policy
Show-PolicyObservations -Policy $policy -MigrationDisplay $migrationDisplay

Write-Section 'PASSKEY DYNAMIC MIGRATION'

$currentValue = Get-PasskeyDynamicMigrationStatus -Policy $policy
$displayValue = if ($null -eq $currentValue) { 'null' } else { $currentValue.ToString().ToLowerInvariant() }

if ($ReportOnly) {
    if ($currentValue -eq $true) {
        Write-Field -Label 'Current value' -Value $displayValue -Color Green
        Write-Status -Level Ok -Text 'passkeyDynamicMigration is already true. A normal run would make no change.'
    }
    else {
        Write-Field -Label 'Current value' -Value $displayValue -Color Yellow
        Write-Status -Level Warn -Text "Current value is $displayValue. A normal run would set passkeyDynamicMigration to true."
    }

    # The value as read, not as verified. -ReportOnly verifies nothing.
    Add-CsvRow -Setting 'passkeyDynamicMigration' -Value $displayValue

    Write-Section 'REPORT ONLY - NO CHANGES MADE'
    Write-Status -Level Skip -Text @(
        '-ReportOnly was specified, so no PATCH was sent and no value was verified.'
        'Rerun without -ReportOnly to apply the opt-out.'
    )

    Export-PolicyCsv

    Write-Host ''
    Write-Host 'The Microsoft Graph session is still connected. Run Disconnect-MgGraph when finished.'
    return
}

if ($currentValue -eq $true) {
    Write-Field -Label 'Current value' -Value 'true' -Color Green
    Write-Status -Level Ok -Text 'passkeyDynamicMigration is already true. No change was required.'
}
else {
    Write-Field -Label 'Current value' -Value $displayValue -Color Yellow
    Write-Status -Level Warn -Text "Current value is $displayValue. Setting passkeyDynamicMigration to true..."

    Set-PasskeyDynamicMigrationOptOut

    Write-Status -Level Info -Text 'Update request sent.'
}

if (-not (Test-PasskeyDynamicMigrationStatus)) {
    # A failed verification is exactly when the collected report is worth
    # keeping, so write it before the run ends.
    Add-CsvRow -Setting 'passkeyDynamicMigration' -Value '(verification failed)'
    Export-PolicyCsv

    throw @'
Verification failed: passkeyDynamicMigration is not true after the operation.

The update request was accepted, but re-reading the policy did not return true.
No other tenant setting was modified.

optOutSettings is absent from Microsoft's published Graph metadata, so its shape
cannot be validated in advance. It may differ in this tenant, or Microsoft may
have changed it. To see what this tenant actually returns, run:

    .\Test-EntraPasskeyOptOutShape.ps1

If optOutSettings is missing or shaped unexpectedly, please report it with that
output at:

    https://github.com/anthonyjohnsonga/entra-passkey-dynamic-migration/issues
'@
}

Write-Status -Level Ok -Text 'Verified against the policy after the operation.'

# The verified value, which is the one worth carrying into a file.
Add-CsvRow -Setting 'passkeyDynamicMigration' -Value 'true'

Write-Section 'FINAL VERIFIED STATUS'
Write-HostColor -Text '{' -Color Green
Write-HostColor -Text '  "passkeyDynamicMigration": true' -Color Green
Write-HostColor -Text '}' -Color Green

Export-PolicyCsv

Write-Host ''
Write-Host 'The Microsoft Graph session is still connected. Run Disconnect-MgGraph when finished.'

#endregion
