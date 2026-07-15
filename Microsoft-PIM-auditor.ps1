<#
.SYNOPSIS
    Interactive PIM Auditor - Authenticates to Azure and audits Azure & Entra ID role assignments.

.DESCRIPTION
    This script checks for the required Azure PowerShell modules, installs them if missing,
    authenticates to Azure via interactive browser login, and provides an interactive menu
    to audit role assignments across Azure subscriptions and Microsoft Entra ID directory roles.

    Features:
    - Azure resource role auditing (MG/Subscription/RG scope)
    - Microsoft Entra ID directory role auditing (including Administrative Units)
    - PIM eligible vs permanent assignment detection
    - HTML report export

.NOTES
    Author: Jędrzej Boguszyński || https://jedrzejboguszynski.pl
    Date: 2026
    Requires: PowerShell 5.1+ or PowerShell 7+
#>

[CmdletBinding()]
param(
    [switch]$VerboseMode
)

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$script:VerboseMode = $VerboseMode

# ── Utility Functions ───────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    if ($Level -eq 'Warning' -and -not $script:VerboseMode) {
        return
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = switch ($Level) {
        'Info'    { "[INFO]" }
        'Warning' { "[WARN]" }
        'Error'   { "[ERROR]" }
    }

    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Write-Header {
    param([string]$Title)

    Clear-Host
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Magenta
    Write-Host ""
}

# ── Module Management ───────────────────────────────────────────────────────

function Test-AzModuleInstalled {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    $module = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
    return ($null -ne $module)
}

function Install-AzModuleIfNeeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    if (Test-AzModuleInstalled -ModuleName $ModuleName) {
        Write-Log "$ModuleName module is already installed."
        return $false
    }

    Write-Log "$ModuleName module is not installed. Installing..." -Level Warning

    try {
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
            Write-Log "Setting PSGallery as trusted repository."
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }

        Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
        Write-Log "$ModuleName module installed successfully."
        return $true
    }
    catch {
        Write-Log "Failed to install $ModuleName module: $($_.Exception.Message)" -Level Error
        throw
    }
}

# ── Authentication ──────────────────────────────────────────────────────────

function Connect-ToAzure {
    [CmdletBinding()]
    param()

    Write-Log "Connecting to Azure via interactive browser login..."
    Write-Log "A browser window will open. Please sign in with your Azure credentials."

    # Save current config and disable subscription picker (non-persistent)
    $originalConfig = $null
    try { $originalConfig = (Get-AzConfig -ErrorAction SilentlyContinue).LoginExperienceV2 } catch {}
    try { Update-AzConfig -LoginExperienceV2 Off -ErrorAction SilentlyContinue | Out-Null } catch {}

    try {
        $context = Connect-AzAccount -SkipContextPopulation -ErrorAction Stop
        Write-Log "Successfully authenticated to Azure."
        Write-Log "Account: $($context.Context.Account.Id)"
        Write-Log "Tenant:  $($context.Context.Tenant.Id)"
        return $context
    }
    catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        # Restore original config
        if ($null -ne $originalConfig) {
            try { Update-AzConfig -LoginExperienceV2 $originalConfig -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
    }
}

# ── Subscription Functions ──────────────────────────────────────────────────

function Show-SubscriptionList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Subscriptions
    )

    Write-Host ""
    Write-Host "Available Azure Subscriptions:" -ForegroundColor Green
    Write-Host ""

    $index = 1
    foreach ($sub in $Subscriptions) {
        $stateColor = if ($sub.State -eq 'Enabled') { 'Green' } else { 'DarkGray' }
        Write-Host "  [$index] " -ForegroundColor White -NoNewline
        Write-Host "$($sub.Name)" -ForegroundColor Cyan -NoNewline
        Write-Host "  ($($sub.Id))  " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($sub.State)" -ForegroundColor $stateColor
        $index++
    }
}

function Get-SubscriptionSelection {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [array]$Subscriptions
    )

    while ($true) {
        Show-SubscriptionList -Subscriptions $Subscriptions

        Write-Host ""
        $choice = Read-Host "Enter subscription number (or 'b' to go back)"

        if ($choice -eq 'b' -or $choice -eq 'B') {
            return $null
        }

        $parsed = 0
        if ([int]::TryParse($choice, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $Subscriptions.Count) {
            return $Subscriptions[$parsed - 1]
        }

        Write-Log "Invalid selection. Please enter a number between 1 and $($Subscriptions.Count)." -Level Warning
        Write-Host ""
    }
}

# ── Role Assignment Audit ───────────────────────────────────────────────────

$HighPrivilegeRoles = @('Owner', 'Contributor', 'User Access Administrator', 'Management Group Contributor')

$HighPrivilegeEntraRoles = @(
    'Global Administrator'
    'Privileged Role Administrator'
    'Privileged Authentication Administrator'
    'Security Administrator'
    'Conditional Access Administrator'
    'Partner Tier2 Support'
    'User Administrator'
    'Application Administrator'
    'Cloud Application Administrator'
    'Hybrid Identity Administrator'
    'Exchange Administrator'
    'SharePoint Administrator'
    'Intune Administrator'
    'Compliance Administrator'
    'Global Reader'
)

function Show-RoleAssignmentTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Assignments,
        [string]$Indent = ''
    )

    if ($Assignments.Count -eq 0) {
        Write-Host "${Indent}  (none)" -ForegroundColor DarkGray
        return
    }

    $Assignments |
        Sort-Object -Property DisplayName |
        Format-Table -Property @(
            @{ Label = 'DisplayName';        Expression = { if ($_.DisplayName) { $_.DisplayName } else { "[Unknown] $($_.ObjectId)" } }; Align = 'Left' }
            @{ Label = 'RoleDefinitionName'; Expression = { $_.RoleDefinitionName }; Align = 'Left' }
            @{ Label = 'ObjectType';         Expression = { $_.ObjectType };         Align = 'Left' }
        ) -AutoSize | Out-String -Width 200 | ForEach-Object { Write-Host "${Indent}$_" -NoNewline }
}

function Get-HighPrivilegePermanentAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [array]$Assignments
    )

    return @($Assignments | Where-Object {
        $_.Status -eq 'Permanent' -and $_.RoleDefinitionName -in $HighPrivilegeRoles
    })
}

function Get-HighPrivilegeEligibleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [array]$Assignments,
        [Parameter(Mandatory)]
        [string]$Scope
    )

    return @($Assignments | Where-Object {
        $_.Status -eq 'Eligible (PIM)' -and $_.RoleDefinitionName -in $HighPrivilegeRoles -and $_.Scope -eq $Scope
    })
}

function Get-SafeRoleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [string]$Scope,
        [string]$Label
    )

    try {
        $result = @(Get-AzRoleAssignment -Scope $Scope -AtScope -ErrorAction Stop)
        foreach ($r in $result) {
            $r | Add-Member -NotePropertyName 'Status' -NotePropertyValue 'Permanent' -Force
            if (-not $r.DisplayName -and $r.ObjectType -eq 'ForeignGroup') {
                $r | Add-Member -NotePropertyName 'DisplayName' -NotePropertyValue "[$($r.ObjectType)] $($r.ObjectId)" -Force
            }
        }
        return $result
    }
    catch {
        if ($_.Exception.Message -match 'NotFound|Forbidden|Unauthorized') {
            Write-Log "  Cannot read role assignments for ${Label}: insufficient permissions or scope not found." -Level Warning
        }
        else {
            Write-Log "  Error reading role assignments for ${Label}: $($_.Exception.Message)" -Level Warning
        }
        return @()
    }
}

function Get-PimEligibleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )

    $uri = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

    try {
        $response = Invoke-AzRestMethod -Path $uri -Method GET -ErrorAction Stop
        if ($response.StatusCode -ne 200) {
            Write-Log "  PIM API returned status $($response.StatusCode). PIM eligible assignments may not be available." -Level Warning
            return @()
        }

        $json = $response.Content | ConvertFrom-Json
        if (-not $json.value -or $json.value.Count -eq 0) {
            return @()
        }

        # Cache role definitions to avoid repeated lookups
        $roleDefCache = @{}
        try {
            $roleDefs = @(Get-AzRoleDefinition -ErrorAction Stop)
            foreach ($rd in $roleDefs) {
                $roleDefCache[$rd.Id] = $rd.Name
            }
        }
        catch {
            Write-Log "  Could not fetch role definitions for PIM mapping: $($_.Exception.Message)" -Level Warning
        }

        $results = @()
        foreach ($entry in $json.value) {
            $props = $entry.properties
            if (-not $props) { continue }

            $roleDefId = $props.roleDefinitionId -replace '.*/', ''
            $principalId = $props.principalId
            $scope = $props.scope

            $roleName = $roleDefCache[$roleDefId]
            if (-not $roleName) { $roleName = $roleDefId }

            # Determine principal type and name
            $objType = $props.principalType
            if (-not $objType) { $objType = 'Unknown' }
            $displayName = $principalId

            # Try to resolve display name via Graph
            try {
                if ($objType -eq 'User') {
                    $user = Get-AzADUser -ObjectId $principalId -ErrorAction SilentlyContinue
                    if ($user) { $displayName = $user.DisplayName }
                }
                elseif ($objType -eq 'Group' -or $objType -eq 'ForeignGroup') {
                    $group = Get-AzADGroup -ObjectId $principalId -ErrorAction SilentlyContinue
                    if ($group) {
                        $displayName = $group.DisplayName
                    }
                    else {
                        $displayName = "[$objType] $principalId"
                    }
                }
                elseif ($objType -eq 'ServicePrincipal') {
                    $sp = Get-AzADServicePrincipal -ObjectId $principalId -ErrorAction SilentlyContinue
                    if ($sp) { $displayName = $sp.DisplayName }
                }
            }
            catch { }

            $results += [PSCustomObject]@{
                DisplayName        = $displayName
                RoleDefinitionName = $roleName
                Scope              = $scope
                ObjectType         = $objType
                Status             = 'Eligible (PIM)'
            }
        }

        return $results
    }
    catch {
        Write-Log "  Failed to query PIM eligible assignments: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-ManagementGroupAncestors {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )

    $uri = "/subscriptions/${SubscriptionId}?api-version=2022-12-01"

    try {
        $response = Invoke-AzRestMethod -Path $uri -Method GET -ErrorAction Stop
        if ($response.StatusCode -ne 200) {
            Write-Log "  Could not retrieve management group info for subscription: HTTP $($response.StatusCode)" -Level Warning
            return @()
        }

        $json = $response.Content | ConvertFrom-Json
        $ancestors = $json.properties.managementGroupAncestors

        if (-not $ancestors -or $ancestors.Count -eq 0) {
            return @()
        }

        # Ancestors are returned closest-first; reverse to get root-first order
        $result = @()
        foreach ($a in $ancestors) {
            $mgId = $a.name
            $mgDisplayName = $a.displayName
            if (-not $mgDisplayName) { $mgDisplayName = $mgId }
            $result += [PSCustomObject]@{
                Id          = "/providers/Microsoft.Management/managementGroups/$mgId"
                Name        = $mgId
                DisplayName = $mgDisplayName
            }
        }

        # Reverse to root-first order (tenant root → ... → direct parent)
        [array]::Reverse($result)
        return $result
    }
    catch {
        Write-Log "  Failed to retrieve management group ancestors: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-ManagementGroupRoleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [string]$ManagementGroupId,
        [string]$ManagementGroupName,
        [array]$PimEligibleCache
    )

    $mgScope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"

    $permanent = Get-SafeRoleAssignments -Scope $mgScope -Label "management group '$ManagementGroupName'"

    $eligibleAtScope = @()
    if ($PimEligibleCache) {
        $eligibleAtScope = @($PimEligibleCache | Where-Object { $_.Scope -eq $mgScope })
    }

    $all = @($permanent) + @($eligibleAtScope)
    return $all
}

function Get-AllRoleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [string]$Scope,
        [string]$Label,
        [string]$SubscriptionId,
        [array]$PimEligibleCache
    )

    $permanent = Get-SafeRoleAssignments -Scope $Scope -Label $Label

    $eligibleAtScope = @()
    if ($PimEligibleCache) {
        $eligibleAtScope = @($PimEligibleCache | Where-Object { $_.Scope -eq $Scope })
    }

    $all = @($permanent) + @($eligibleAtScope)
    return $all
}

function Invoke-SubscriptionAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Subscription,
        [ref]$ResourcesModuleInstalled
    )

    Write-Log "Switching to subscription '$($Subscription.Name)'..."

    $targetTenant = $Subscription.TenantId
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue

    if ($currentContext.Tenant.Id -ne $targetTenant) {
        Write-Log "Subscription is in tenant $targetTenant (current: $($currentContext.Tenant.Id)). Re-authenticating..."
        try {
            Connect-AzAccount -TenantId $targetTenant -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Log "Failed to authenticate to tenant ${targetTenant}: $($_.Exception.Message)" -Level Error
            return
        }
    }

    try {
        $ctx = Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop
        Write-Log "Context set to subscription '$($ctx.Subscription.Name)' ($($ctx.Subscription.Id))."
    }
    catch {
        Write-Log "Failed to select subscription: $($_.Exception.Message)" -Level Error
        return
    }

    if (-not $ResourcesModuleInstalled.Value) {
        $installed = Install-AzModuleIfNeeded -ModuleName 'Az.Resources'
        if ($installed) {
            Import-Module 'Az.Resources' -ErrorAction Stop | Out-Null
        }
        $ResourcesModuleInstalled.Value = $true
    }

    $subScope = "/subscriptions/$($Subscription.Id)"

    # ── Fetch PIM eligible assignments once for the entire subscription ────

    Write-Log "Fetching PIM eligible assignments for subscription '$($Subscription.Name)'..."
    $pimEligibleCache = @(Get-PimEligibleAssignments -SubscriptionId $Subscription.Id)
    Write-Log "Found $($pimEligibleCache.Count) PIM eligible assignment(s) across the subscription."

    # ── Collect all high-privilege assignments ──────────────────────────────

    $allHighPerm = @()
    $allHighElig = @()

    # ── Management Group Hierarchy (root-first) ─────────────────────────────

    Write-Log "Discovering management group hierarchy..."
    $mgAncestors = @(Get-ManagementGroupAncestors -SubscriptionId $Subscription.Id)

    $mgPath = ""
    foreach ($mg in $mgAncestors) {
        if ($mgPath) { $mgPath += " / " }
        $mgPath += "MG: $($mg.DisplayName)"
    }

    $subPath = if ($mgPath) { "$mgPath / Sub: $($Subscription.Name)" } else { "Sub: $($Subscription.Name)" }

    foreach ($mg in $mgAncestors) {
        Write-Log "  Querying management group '$($mg.DisplayName)'..."
        $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
        $mgAssignments = @(Get-ManagementGroupRoleAssignments -ManagementGroupId $mg.Name -ManagementGroupName $mg.DisplayName -PimEligibleCache $pimEligibleCache)

        # Scope for this MG = everything up to and including this MG
        $thisMgPath = ""
        $found = $false
        foreach ($ancestor in $mgAncestors) {
            if ($ancestor.Name -eq $mg.Name) { $found = $true }
            if ($thisMgPath) { $thisMgPath += " / " }
            $thisMgPath += "MG: $($ancestor.DisplayName)"
            if ($found) { break }
        }

        $mgPerm = @(Get-HighPrivilegePermanentAssignments -Assignments $mgAssignments)
        $mgElig = @(Get-HighPrivilegeEligibleAssignments -Assignments $pimEligibleCache -Scope $mgScope)

        foreach ($item in $mgPerm) { $item | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $thisMgPath -Force }
        foreach ($item in $mgElig) { $item | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $thisMgPath -Force }
        $allHighPerm += $mgPerm
        $allHighElig += $mgElig
    }

    # ── Subscription-Level ──────────────────────────────────────────────────

    Write-Log "Fetching subscription-level role assignments..."
    $subAssignments = Get-AllRoleAssignments -Scope $subScope -Label "subscription '$($Subscription.Name)'" -PimEligibleCache $pimEligibleCache

    $subPerm = @(Get-HighPrivilegePermanentAssignments -Assignments $subAssignments)
    $subElig = @(Get-HighPrivilegeEligibleAssignments -Assignments $pimEligibleCache -Scope $subScope)

    foreach ($item in $subPerm) { $item | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $subPath -Force }
    foreach ($item in $subElig) { $item | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $subPath -Force }
    $allHighPerm += $subPerm
    $allHighElig += $subElig

    # ── Resource Groups ─────────────────────────────────────────────────────

    Write-Log "Enumerating resource groups..."
    $resourceGroups = @()
    try {
        $resourceGroups = @(Get-AzResourceGroup -ErrorAction Stop | Sort-Object -Property ResourceGroupName)
    }
    catch {
        Write-Log "Failed to enumerate resource groups: $($_.Exception.Message)" -Level Warning
    }

    $rgIndex = 0
    foreach ($rg in $resourceGroups) {
        $rgIndex++
        Write-Log "  [$rgIndex/$($resourceGroups.Count)] Processing '$($rg.ResourceGroupName)'..."

        $rgAssignments = Get-AllRoleAssignments -Scope $rg.ResourceId -Label "RG '$($rg.ResourceGroupName)'" -PimEligibleCache $pimEligibleCache

        $rgPerm = @(Get-HighPrivilegePermanentAssignments -Assignments $rgAssignments)
        $rgElig = @(Get-HighPrivilegeEligibleAssignments -Assignments $pimEligibleCache -Scope $rg.ResourceId)

        $rgScope = "RG: $($rg.ResourceGroupName)"
        foreach ($item in $rgPerm) { $item | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $rgScope -Force }
        foreach ($item in $rgElig) { $item | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $rgScope -Force }
        $allHighPerm += $rgPerm
        $allHighElig += $rgElig
    }

    # ── Display Results ─────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "=== Audit: '$($Subscription.Name)' ($($Subscription.Id)) ===" -ForegroundColor Magenta

    # Helper: display a grouped table with separators
    function Show-GroupedTable {
        param(
            [array]$Items,
            [string]$Title
        )

        if ($Items.Count -eq 0) { return }

        Write-Host ""
        Write-Host "$Title ($($Items.Count)):" -ForegroundColor Green

        $sorted = $Items | Sort-Object Scope, DisplayName
        $lastScope = $null

        foreach ($item in $sorted) {
            if ($lastScope -and $item.Scope -ne $lastScope) {
                Write-Host "  ---" -ForegroundColor DarkGray
            }
            $lastScope = $item.Scope

            $displayName = if ($item.DisplayName) { $item.DisplayName } else { "[Unknown] $($item.ObjectId)" }
            Write-Host ("  {0,-50} {1,-30} {2}" -f $item.Scope, $displayName, $item.RoleDefinitionName)
        }
    }

    Show-GroupedTable -Items $allHighPerm -Title "High-Privileged Permanent Assignments"
    Show-GroupedTable -Items $allHighElig -Title "High-Privileged Eligible Assignments (PIM)"

    if ($allHighPerm.Count -eq 0 -and $allHighElig.Count -eq 0) {
        Write-Host ""
        Write-Host "No high-privilege permanent or eligible assignments found." -ForegroundColor DarkGray
    }

    # ── Audit Summary ───────────────────────────────────────────────────────

    $totalPermanent = $allHighPerm.Count
    $totalEligible = $allHighElig.Count
    $totalAll = $totalPermanent + $totalEligible
    $pimPct = if ($totalAll -gt 0) { [math]::Round(($totalEligible / $totalAll) * 100, 1) } else { 0 }

    Write-Host ""
    Write-Host "=== Audit Summary ===" -ForegroundColor Magenta
    Write-Host "  Permanent assignments:    $totalPermanent" -ForegroundColor White
    Write-Host "  PIM eligible assignments: $totalEligible" -ForegroundColor White
    Write-Host "  Total:                    $totalAll" -ForegroundColor White
    Write-Host "  PIM % coverage:          ${pimPct}%" -ForegroundColor White

    # ── Post-Audit Menu ───────────────────────────────────────────────────

    while ($true) {
        $choice = Show-PostAuditMenu

        switch ($choice) {
            '1' {
                $reportPath = Export-AuditReport -SubscriptionName $Subscription.Name -SubscriptionId $Subscription.Id -PermanentAssignments $allHighPerm -EligibleAssignments $allHighElig
                Write-Host ""
                Write-Log "Report saved to: $reportPath" -Level Info
                break
            }
            '2' {
                break
            }
            default {
                Write-Log "Invalid choice. Please enter 1 or 2." -Level Warning
                Start-Sleep -Seconds 1
                continue
            }
        }
        break
    }
}

# ── Entra ID Audit Functions ───────────────────────────────────────────────

function Get-EntraPrincipalName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$PrincipalId,
        [string]$PrincipalType
    )

    try {
        switch ($PrincipalType) {
            'User' {
                $user = Get-MgUser -UserId $PrincipalId -ErrorAction SilentlyContinue
                if ($user) { return $user.UserPrincipalName }
            }
            'Group' {
                $group = Get-MgGroup -GroupId $PrincipalId -ErrorAction SilentlyContinue
                if ($group) { return $group.DisplayName }
            }
            'ServicePrincipal' {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue
                if ($sp) { return $sp.DisplayName }
            }
        }

        # Fallback: try all methods if type didn't match
        $user = Get-MgUser -UserId $PrincipalId -ErrorAction SilentlyContinue
        if ($user) { return $user.UserPrincipalName }

        $group = Get-MgGroup -GroupId $PrincipalId -ErrorAction SilentlyContinue
        if ($group) { return $group.DisplayName }

        $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue
        if ($sp) { return $sp.DisplayName }
    }
    catch {
        # Ignore errors - will return Unknown
    }

    return "Unknown ($PrincipalId)"
}

function Get-EntraPermanentRoleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    Write-Log "Fetching permanent Entra ID role assignments..."

    $assignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)

    if ($assignments.Count -eq 0) {
        Write-Log "No permanent Entra ID role assignments found."
        return @()
    }

    Write-Log "Fetching role definitions..."
    $roleDefs = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction SilentlyContinue)
    $roleDefMap = @{}
    foreach ($rd in $roleDefs) { $roleDefMap[$rd.Id] = $rd.DisplayName }

    $filtered = @($assignments | Where-Object {
        $roleName = $roleDefMap[$_.RoleDefinitionId]
        $roleName -in $HighPrivilegeEntraRoles
    })

    if ($filtered.Count -eq 0) {
        Write-Log "No high-privilege permanent Entra ID role assignments found."
        return @()
    }

    Write-Log "Found $($filtered.Count) privileged assignment(s). Resolving principals..."

    $results = @()
    $index = 0
    foreach ($assignment in $filtered) {
        $index++
        $roleName = $roleDefMap[$assignment.RoleDefinitionId]
        $principalId = $assignment.PrincipalId

        if ($index % 10 -eq 0 -or $index -eq $filtered.Count) {
            Write-Log "  [$index/$($filtered.Count)] Resolving principals..."
        }

        $principalName = Get-EntraPrincipalName -PrincipalId $principalId -PrincipalType ''
        $scope = if ($assignment.DirectoryScopeId -eq '/') { 'Directory' } else { "AU: $($assignment.DirectoryScopeId)" }

        # Determine type from the resolved principal
        $resolvedType = 'Unknown'
        try {
            $u = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
            if ($u) { $resolvedType = 'User' }
            else {
                $g = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                if ($g) { $resolvedType = 'Group' }
                else {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                    if ($sp) { $resolvedType = 'ServicePrincipal' }
                }
            }
        }
        catch {}

        $results += [PSCustomObject]@{
            PrincipalName  = $principalName
            RoleName       = $roleName
            PrincipalType  = $resolvedType
            Scope          = $scope
            Status         = 'Permanent'
            AssignmentId   = $assignment.Id
        }
    }

    return $results
}

function Get-EntraPimEligibleAssignments {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    Write-Log "Fetching PIM eligible Entra ID role assignments..."

    try {
        $assignments = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty RoleDefinition -ErrorAction Stop)
    }
    catch {
        Write-Log "Could not retrieve PIM eligible assignments (PIM may not be licensed): $($_.Exception.Message)" -Level Warning
        return @()
    }

    if ($assignments.Count -eq 0) {
        Write-Log "No PIM eligible Entra ID role assignments found."
        return @()
    }

    Write-Log "Found $($assignments.Count) PIM eligible Entra ID role assignment(s)."

    $roleDefs = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction SilentlyContinue)
    $roleDefMap = @{}
    foreach ($rd in $roleDefs) { $roleDefMap[$rd.Id] = $rd.DisplayName }

    $filtered = @($assignments | Where-Object {
        $roleName = $roleDefMap[$_.RoleDefinitionId]
        $roleName -in $HighPrivilegeEntraRoles
    })

    if ($filtered.Count -eq 0) {
        Write-Log "No high-privilege PIM eligible Entra ID role assignments found."
        return @()
    }

    Write-Log "Resolving principals..."

    $results = @()
    $index = 0
    foreach ($assignment in $filtered) {
        $index++
        $roleName = $roleDefMap[$assignment.RoleDefinitionId]
        $principalId = $assignment.PrincipalId

        if ($index % 10 -eq 0 -or $index -eq $filtered.Count) {
            Write-Log "  [$index/$($filtered.Count)] Resolving principals..."
        }

        $principalName = Get-EntraPrincipalName -PrincipalId $principalId -PrincipalType ''
        $scope = if ($assignment.DirectoryScopeId -eq '/') { 'Directory' } else { "AU: $($assignment.DirectoryScopeId)" }

        # Determine type from the resolved principal
        $resolvedType = 'Unknown'
        try {
            $u = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
            if ($u) { $resolvedType = 'User' }
            else {
                $g = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                if ($g) { $resolvedType = 'Group' }
                else {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                    if ($sp) { $resolvedType = 'ServicePrincipal' }
                }
            }
        }
        catch {}

        $results += [PSCustomObject]@{
            PrincipalName  = $principalName
            RoleName       = $roleName
            PrincipalType  = $resolvedType
            Scope          = $scope
            Status         = 'Eligible (PIM)'
            StartDateTime  = $assignment.StartDateTime
            EndDateTime    = $assignment.EndDateTime
            AssignmentId   = $assignment.Id
        }
    }

    return $results
}

function Invoke-EntraAudit {
    [CmdletBinding()]
    param()

    Write-Log "Starting Microsoft Entra ID audit..."

    # ── Ensure Microsoft.Graph module is available ──────────────────────────

    $installed = Install-AzModuleIfNeeded -ModuleName 'Microsoft.Graph.Authentication'
    if ($installed) {
        Import-Module 'Microsoft.Graph.Authentication' -ErrorAction Stop | Out-Null
    }
    $installed2 = Install-AzModuleIfNeeded -ModuleName 'Microsoft.Graph.Identity.Governance'
    if ($installed2) {
        Import-Module 'Microsoft.Graph.Identity.Governance' -ErrorAction Stop | Out-Null
    }
    $installed3 = Install-AzModuleIfNeeded -ModuleName 'Microsoft.Graph.Users'
    if ($installed3) {
        Import-Module 'Microsoft.Graph.Users' -ErrorAction Stop | Out-Null
    }
    $installed4 = Install-AzModuleIfNeeded -ModuleName 'Microsoft.Graph.Groups'
    if ($installed4) {
        Import-Module 'Microsoft.Graph.Groups' -ErrorAction Stop | Out-Null
    }
    $installed5 = Install-AzModuleIfNeeded -ModuleName 'Microsoft.Graph.Applications'
    if ($installed5) {
        Import-Module 'Microsoft.Graph.Applications' -ErrorAction Stop | Out-Null
    }

    # ── Connect to Microsoft Graph ─────────────────────────────────────────

    $mgContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $mgContext) {
        Write-Log "Connecting to Microsoft Graph..."
        try {
            Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'Directory.Read.All' -ErrorAction Stop | Out-Null
            Write-Log "Successfully connected to Microsoft Graph."
        }
        catch {
            Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
            return
        }
    }
    else {
        Write-Log "Already connected to Microsoft Graph as $($mgContext.Account)."
    }

    # ── Verify connectivity ────────────────────────────────────────────────

    Write-Log "Verifying Graph API connectivity..."
    try {
        $org = Get-MgOrganization -ErrorAction Stop
        if ($org) {
            Write-Log "  Connected to tenant: $($org.DisplayName) ($($org.Id))"
        }
    }
    catch {
        Write-Log "  ERROR: Could not verify tenant: $($_.Exception.Message)" -Level Error
        return
    }

    # ── Fetch all role assignments ────────────────────────────────────────────

    $permanentAssignments = @(Get-EntraPermanentRoleAssignments)
    $eligibleAssignments = @(Get-EntraPimEligibleAssignments)

    # ── Filter to high-privilege roles ────────────────────────────────────────

    $highPerm = @($permanentAssignments | Where-Object { $_.RoleName -in $HighPrivilegeEntraRoles })
    $highElig = @($eligibleAssignments | Where-Object { $_.RoleName -in $HighPrivilegeEntraRoles })

    Write-Log "High-privilege permanent: $($highPerm.Count), High-privilege eligible: $($highElig.Count)"

    # ── Display Results ───────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "=== Microsoft Entra ID Audit ===" -ForegroundColor Magenta

    # Helper: display a grouped table with separators
    function Show-EntraGroupedTable {
        param(
            [array]$Items,
            [string]$Title
        )

        if ($Items.Count -eq 0) { return }

        Write-Host ""
        Write-Host "$Title ($($Items.Count)):" -ForegroundColor Green

        $sorted = $Items | Sort-Object RoleName, PrincipalName
        $lastRole = $null

        foreach ($item in $sorted) {
            if ($lastRole -and $item.RoleName -ne $lastRole) {
                Write-Host "  ---" -ForegroundColor DarkGray
            }
            $lastRole = $item.RoleName

            Write-Host ("  {0,-45} {1,-40} {2}" -f $item.RoleName, $item.PrincipalName, $item.PrincipalType)
        }
    }

    Show-EntraGroupedTable -Items $highPerm -Title "High-Privileged Permanent Assignments"
    Show-EntraGroupedTable -Items $highElig -Title "High-Privileged Eligible Assignments (PIM)"

    if ($highPerm.Count -eq 0 -and $highElig.Count -eq 0) {
        Write-Host ""
        Write-Host "No high-privilege permanent or eligible assignments found." -ForegroundColor DarkGray
    }

    # ── Audit Summary ─────────────────────────────────────────────────────────

    $totalPermanent = $highPerm.Count
    $totalEligible = $highElig.Count
    $totalAll = $totalPermanent + $totalEligible
    $pimPct = if ($totalAll -gt 0) { [math]::Round(($totalEligible / $totalAll) * 100, 1) } else { 0 }

    Write-Host ""
    Write-Host "=== Audit Summary ===" -ForegroundColor Magenta
    Write-Host "  Permanent assignments:    $totalPermanent" -ForegroundColor White
    Write-Host "  PIM eligible assignments: $totalEligible" -ForegroundColor White
    Write-Host "  Total:                    $totalAll" -ForegroundColor White
    Write-Host "  PIM % coverage:          ${pimPct}%" -ForegroundColor White

    # ── Post-Audit Menu ───────────────────────────────────────────────────────

    while ($true) {
        $choice = Show-PostAuditMenu

        switch ($choice) {
            '1' {
                $context = Get-AzContext -ErrorAction SilentlyContinue
                $tenantId = if ($context) { $context.Tenant.Id } else { 'Unknown' }
                $reportPath = Export-AuditReport -SubscriptionName "Entra ID - $tenantId" -SubscriptionId $tenantId -PermanentAssignments $highPerm -EligibleAssignments $highElig -ScopeType 'Entra'
                Write-Host ""
                Write-Log "Report saved to: $reportPath" -Level Info
                break
            }
            '2' {
                break
            }
            default {
                Write-Log "Invalid choice. Please enter 1 or 2." -Level Warning
                Start-Sleep -Seconds 1
                continue
            }
        }
        break
    }
}

# ── HTML Export ────────────────────────────────────────────────────────────

function Export-AuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionName,
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [array]$PermanentAssignments,
        [array]$EligibleAssignments,
        [string]$ScopeType = 'Azure'
    )

    $reportsDir = Join-Path $PSScriptRoot 'reports'
    if (-not (Test-Path $reportsDir)) {
        New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $safeName = $SubscriptionName -replace '[\\/:*?"<>|]', '_'
    $fileName = "Audit-Report_${safeName}_${timestamp}.html"
    $filePath = Join-Path $reportsDir $fileName

    $totalPerm = $PermanentAssignments.Count
    $totalElig = $EligibleAssignments.Count
    $totalAll = $totalPerm + $totalElig
    $pimPct = if ($totalAll -gt 0) { [math]::Round(($totalElig / $totalAll) * 100, 1) } else { 0 }

    $isEntra = $ScopeType -eq 'Entra'
    $reportTitle = if ($isEntra) { "Microsoft Entra ID Audit Report" } else { "Azure PIM Audit Report" }
    $scopeLabel = if ($isEntra) { "Tenant" } else { "Subscription" }

    function Build-TableRows {
        param([array]$Items, [bool]$IsEntra)
        $rows = @()
        $lastKey = $null
        foreach ($item in ($Items | Sort-Object { if ($IsEntra) { $_.RoleName } else { $_.Scope } }, { if ($IsEntra) { $_.PrincipalName } else { $_.DisplayName } })) {
            $key = if ($IsEntra) { $item.RoleName } else { $item.Scope }
            $scopeClass = if ($key -ne $lastKey) { 'scope-change' } else { '' }
            $lastKey = $key

            if ($IsEntra) {
                $col1 = [System.Web.HttpUtility]::HtmlEncode($item.RoleName)
                $col2 = [System.Web.HttpUtility]::HtmlEncode($item.PrincipalName)
                $col3 = [System.Web.HttpUtility]::HtmlEncode($item.PrincipalType)
                $col4 = [System.Web.HttpUtility]::HtmlEncode($item.Scope)
                $rows += "<tr class=`"$scopeClass`"><td>$col1</td><td>$col2</td><td>$col3</td><td>$col4</td></tr>"
            }
            else {
                $col1 = [System.Web.HttpUtility]::HtmlEncode($item.Scope)
                $col2 = if ($item.DisplayName) { [System.Web.HttpUtility]::HtmlEncode($item.DisplayName) } else { "[Unknown] $($item.ObjectId)" }
                $col3 = [System.Web.HttpUtility]::HtmlEncode($item.RoleDefinitionName)
                $col4 = [System.Web.HttpUtility]::HtmlEncode($item.ObjectType)
                $rows += "<tr class=`"$scopeClass`"><td>$col1</td><td>$col2</td><td>$col3</td><td>$col4</td></tr>"
            }
        }
        return $rows -join "`n"
    }

    $permRows = if ($PermanentAssignments.Count -gt 0) { Build-TableRows -Items $PermanentAssignments -IsEntra $isEntra } else { '<tr><td colspan="4" class="empty">No high-privilege permanent assignments found</td></tr>' }
    $eligRows = if ($EligibleAssignments.Count -gt 0) { Build-TableRows -Items $EligibleAssignments -IsEntra $isEntra } else { '<tr><td colspan="4" class="empty">No high-privilege eligible assignments found</td></tr>' }

    $tableHeaders = if ($isEntra) {
        '<tr><th>Role</th><th>Principal</th><th>Type</th><th>Scope</th></tr>'
    } else {
        '<tr><th>Scope</th><th>Display Name</th><th>Role</th><th>Type</th></tr>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$reportTitle - $SubscriptionName</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; color: #333; padding: 30px; }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { background: linear-gradient(135deg, #0078d4, #005a9e); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }
  .header h1 { font-size: 24px; margin-bottom: 10px; }
  .header .meta { font-size: 14px; opacity: 0.9; }
  .header .meta span { margin-right: 20px; }
  .summary { display: flex; gap: 20px; margin-bottom: 30px; }
  .summary-card { flex: 1; background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
  .summary-card .value { font-size: 32px; font-weight: bold; color: #0078d4; }
  .summary-card .label { font-size: 13px; color: #666; margin-top: 5px; }
  .summary-card.pim .value { color: #107c10; }
  .section { background: white; border-radius: 8px; padding: 25px; margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  .section h2 { font-size: 18px; color: #0078d4; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; }
  .section h2 .count { font-weight: normal; color: #888; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { background: #f8f9fa; text-align: left; padding: 12px 15px; font-weight: 600; color: #555; border-bottom: 2px solid #e0e0e0; }
  td { padding: 10px 15px; border-bottom: 1px solid #f0f0f0; }
  tr:hover { background: #f8f9fa; }
  tr.scope-change td { border-top: 2px solid #e0e0e0; }
  .empty { text-align: center; color: #888; padding: 30px !important; }
  .footer { text-align: center; color: #888; font-size: 12px; margin-top: 30px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>$reportTitle</h1>
    <div class="meta">
      <span>${scopeLabel}: <strong>$SubscriptionName</strong></span>
      <span>ID: $SubscriptionId</span>
      <span>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
    </div>
  </div>

  <div class="summary">
    <div class="summary-card">
      <div class="value">$totalPerm</div>
      <div class="label">Permanent Assignments</div>
    </div>
    <div class="summary-card pim">
      <div class="value">$totalElig</div>
      <div class="label">PIM Eligible</div>
    </div>
    <div class="summary-card">
      <div class="value">$totalAll</div>
      <div class="label">Total</div>
    </div>
    <div class="summary-card pim">
      <div class="value">${pimPct}%</div>
      <div class="label">PIM Coverage</div>
    </div>
  </div>

  <div class="section">
    <h2>High-Privileged Permanent Assignments <span class="count">($totalPerm)</span></h2>
    <table>
      <thead>
        $tableHeaders
      </thead>
      <tbody>
        $permRows
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>High-Privileged Eligible Assignments (PIM) <span class="count">($totalElig)</span></h2>
    <table>
      <thead>
        $tableHeaders
      </thead>
      <tbody>
        $eligRows
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by PIM Auditor
  </div>
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $filePath -Encoding UTF8 -Force
    return $filePath
}

function Show-PostAuditMenu {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Write-Host ""
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Export HTML Report" -ForegroundColor White
    Write-Host "  [2] Exit to Main Menu" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Enter choice (1-2)"
    return $choice
}

# ── Main Menu ───────────────────────────────────────────────────────────────

function Show-MainMenu {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$AccountName,
        [string]$TenantId
    )

    Write-Host ""
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Audit Azure Subscription" -ForegroundColor White
    Write-Host "  [2] Audit Microsoft Entra ID" -ForegroundColor White
    Write-Host "  [3] Exit" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Enter choice (1-3)"
    return $choice
}

# ── Main Execution ──────────────────────────────────────────────────────────

try {
    Write-Header -Title "Microsoft PIM Auditor"

    Write-Log "Checking for required Azure PowerShell modules..."
    Install-AzModuleIfNeeded -ModuleName 'Az.Accounts' | Out-Null
    Import-Module 'Az.Accounts' -MinimumVersion '0.0.1' -ErrorAction Stop | Out-Null

    $context = Connect-ToAzure
    $accountName = $context.Context.Account.Id
    $tenantId = $context.Context.Tenant.Id

    $subs = @(Get-AzSubscription -ErrorAction SilentlyContinue | Sort-Object -Property Name)
    if ($subs.Count -gt 0) {
        Set-AzContext -SubscriptionId $subs[0].Id -ErrorAction SilentlyContinue | Out-Null
    }

    $resourcesModuleInstalled = $false

    while ($true) {
        Write-Header -Title "Microsoft PIM Auditor"

        Write-Host "Connected as: " -NoNewline
        Write-Host "$accountName" -ForegroundColor Cyan
        Write-Host "Tenant:       " -NoNewline
        Write-Host "$tenantId" -ForegroundColor Cyan

        $choice = Show-MainMenu -AccountName $accountName -TenantId $tenantId

        switch ($choice) {
            '1' {
                try {
                    $subs = @(Get-AzSubscription -ErrorAction Stop | Sort-Object -Property Name)
                }
                catch {
                    Write-Log "Failed to retrieve subscriptions: $($_.Exception.Message)" -Level Error
                    Start-Sleep -Seconds 2
                    continue
                }

                if ($subs.Count -eq 0) {
                    Write-Log "No subscriptions found for the current account." -Level Warning
                    Start-Sleep -Seconds 2
                    continue
                }

                $selected = Get-SubscriptionSelection -Subscriptions $subs

                if ($null -eq $selected) {
                    continue
                }

                Invoke-SubscriptionAudit -Subscription $selected -ResourcesModuleInstalled ([ref]$resourcesModuleInstalled)

                Write-Host ""
                Write-Log "Press any key to return to the main menu..."
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            '2' {
                Invoke-EntraAudit

                Write-Host ""
                Write-Log "Press any key to return to the main menu..."
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            '3' {
                Write-Host ""
                Write-Log "Disconnecting from Azure..."
                try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
                Write-Log "Goodbye!"
                exit 0
            }
            default {
                Write-Log "Invalid choice. Please enter 1, 2, or 3." -Level Warning
                Start-Sleep -Seconds 1
            }
        }
    }
}
catch {
    Write-Host ""
    Write-Log "Script failed: $($_.Exception.Message)" -Level Error
    exit 1
}
