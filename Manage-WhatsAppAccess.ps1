#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Manages WhatsApp access control in Active Directory based on a third-party audit API.

.DESCRIPTION
    This script integrates with any REST API that returns users and their WhatsApp
    connection status (connected/disconnected). Based on that status, it automatically
    adds or removes users from AD navigation groups, deauthenticates active firewall
    sessions via the FortiGate REST API, and maintains a local audit trail for
    delta-based execution.

    The script is designed to run on a schedule (e.g., every 5–15 minutes via Task
    Scheduler or a systemd timer on a Windows Server).

.PARAMETER None
    All configuration is loaded from config.ps1 and credentials.json.

.NOTES
    Author  : Henry Victor Passold Gomes
    Version : 3.0.01
    License : GNU General Public License v3.0
    Requires: ActiveDirectory module, PowerShell 5.1+ or 7+

.LINK
    https://github.com/imHenrybtw
#>

#region ── Dependencies & Preferences ──────────────────────────────────────────
Import-Module ActiveDirectory

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$VerbosePreference     = "SilentlyContinue"
$DebugPreference       = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"
#endregion

#region ── Configuration ───────────────────────────────────────────────────────
# Script root paths
$scriptPath  = "C:\Scripts\WhatsAppAccess"
$scriptLog   = "$scriptPath\logs"
$logFiles    = @{
    Validation = "$scriptLog\validation.log"
    AD         = "$scriptLog\ad-changes.log"
    Firewall   = "$scriptLog\firewall-deauth.log"
    Status     = "$scriptLog\status.log"
}
$logGeneral       = "$scriptPath\logs\general.log"
$auditPath        = "$scriptPath\data"
$auditFile        = "$auditPath\audit.json"
$tempAuditFile    = "$auditPath\audit-temp.json"
$credentialsPath  = "$scriptPath\credentials.json"
$keyPath          = "$scriptPath\aes.key"

# ── Active Directory ──
# Your domain FQDN (e.g. "corp.example.com")
$ADServer    = "corp.example.com"

# Search base for all AD queries
$ADSearchBase = "DC=corp,DC=example,DC=com"

# Search base where the four navigation groups live
$GroupSearchBase = "OU=InternetGroups,DC=corp,DC=example,DC=com"

# OUs whose members must never receive navigation groups
# (disabled accounts OU, shared mailbox OU, etc.)
$ExcludedOUs = @(
    "OU=DisabledAccounts,DC=corp,DC=example,DC=com"
    "OU=SharedMailboxes,DC=corp,DC=example,DC=com"
)

# Exception OUs: treated as Admin profile even without a company e-mail
$AdminExceptionOUSuffixes = @(
    "OU=SpecialTeamA,DC=corp,DC=example,DC=com"
    "OU=SpecialTeamB,DC=corp,DC=example,DC=com"
)

# E-mail domain that marks a user as "Admin" profile
$AdminEmailDomain = "@corp.example.com"

# Navigation group names  (must exist in $GroupSearchBase)
$GroupNames = @{
    AdminWhats      = "G_Internet_Admin_WhatsApp"
    OperatorWhats   = "G_Internet_Operator_WhatsApp"
    AdminNoWhats    = "G_Internet_Admin"
    OperatorNoWhats = "G_Internet_Operator"
}

# AD group-name prefix used to detect navigation groups on a user object
$NavGroupPrefix = "g_internet_"

# When a user disconnects, also assign them to the "NoWhats" group
$AssignNonWhatsOnDisconnect = $true

# ── Audit API ──
# Replace with your audit tool's authentication and user-list endpoints.
# The /users endpoint must return JSON with the shape:
#   { "data": [ { "matricula": "jdoe", "conectado": true }, … ] }
$ApiUrlLogin = "https://audit-api.example.com/v1/auth/login"
$ApiUrlUsers = "https://audit-api.example.com/v1/users/disconnected"

# ── FortiGate firewalls ──
# Add one entry per site. Tokens are loaded from credentials.json at runtime.
$FirewallSites = @(
    @{ Name = "HQ";       URL = "https://firewall-hq.example.com"     }
    @{ Name = "Branch01"; URL = "https://firewall-br01.example.com"   }
    @{ Name = "Branch02"; URL = "https://firewall-br02.example.com"   }
)
#endregion

#region ── Logging ─────────────────────────────────────────────────────────────
function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')]
        [string]$Level    = 'INFO',
        [ValidateSet('Validation','AD','Firewall','Status')]
        [string]$Category = 'Validation',
        [switch]$Show
    )

    if (-not $logFiles.ContainsKey($Category)) {
        throw "Log category '$Category' is not mapped in `$logFiles`."
    }

    $logFile = $logFiles[$Category]
    $dir     = Split-Path -Path $logFile -Parent

    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Add-Content -LiteralPath $logFile -Value $logMessage -Encoding UTF8

    if ($Show.IsPresent) {
        $color = switch ($Level) {
            'SUCCESS' { 'Green'  }
            'WARNING' { 'Yellow' }
            'ERROR'   { 'Red'    }
            default   { 'White'  }
        }
        Write-Host $logMessage -ForegroundColor $color
    }

    Write-Verbose "Log written to '$logFile' (Category=$Category; Level=$Level)"
}
#endregion

#region ── Credential helpers ──────────────────────────────────────────────────
function ConvertFrom-SecureStringToPlainText {
    param([SecureString]$SecureString)

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return $SecureString | ConvertFrom-SecureString -AsPlainText
    }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-DecryptedCredentials {
    <#
    .SYNOPSIS
        Loads and decrypts credentials stored in credentials.json using a local AES key.
    .NOTES
        Use Save-Credentials.ps1 (included in /tools) to generate credentials.json and aes.key.
    #>
    foreach ($file in @(
        @{ Path = $credentialsPath; Name = "Credentials file" }
        @{ Path = $keyPath;         Name = "AES key file"     }
    )) {
        if (-not (Test-Path $file.Path)) {
            throw "$($file.Name) not found: $($file.Path)"
        }
    }

    try {
        [byte[]]$aesKey      = [System.IO.File]::ReadAllBytes($keyPath)
        $encryptedData       = Get-Content $credentialsPath -Raw | ConvertFrom-Json

        $creds = @{
            ApiKey         = ConvertFrom-SecureStringToPlainText (ConvertTo-SecureString $encryptedData.ApiKey    -Key $aesKey)
            ApiSecret      = ConvertFrom-SecureStringToPlainText (ConvertTo-SecureString $encryptedData.ApiSecret -Key $aesKey)
            FirewallTokens = @{}
        }

        foreach ($key in $encryptedData.FirewallTokens.PSObject.Properties.Name) {
            $creds.FirewallTokens[$key] = ConvertFrom-SecureStringToPlainText (
                ConvertTo-SecureString $encryptedData.FirewallTokens.$key -Key $aesKey
            )
        }

        return $creds
    }
    catch {
        throw "Failed to decrypt credentials: $($_.Exception.Message)"
    }
}
#endregion

#region ── Initialisation ──────────────────────────────────────────────────────
function Initialize-ScriptEnvironment {
    Write-Host "=== Initialising script environment ===" -ForegroundColor Cyan

    $logFiles.Values | Where-Object { Test-Path $_ } | ForEach-Object {
        Remove-Item $_ -Force
        Write-Host "Previous log removed: $_" -ForegroundColor Green
    }

    foreach ($dir in @($auditPath)) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Log -Message "Directory created: $dir" -Level SUCCESS -Category Validation -Show
            }
            catch {
                Write-Log -Message "Failed to create directory $dir : $_" -Level ERROR -Category Validation -Show
                throw
            }
        }
    }

    Write-Log -Message "=== EXECUTION STARTED ===" -Level INFO -Category Validation -Show
}
#endregion

#region ── Audit API ───────────────────────────────────────────────────────────
function Connect-AuditAPI {
    <#
    .SYNOPSIS
        Authenticates against the configured audit API and returns a bearer token.
    #>
    try {
        Write-Log -Message "Authenticating with audit API..." -Level INFO -Category Validation -Show

        $body     = @{ key = $script:Creds.ApiKey; secret = $script:Creds.ApiSecret } | ConvertTo-Json -Depth 5
        $response = Invoke-RestMethod -Uri $ApiUrlLogin -Method Post -Body $body -ContentType 'application/json'

        if (-not $response.data) { throw "Token not returned by the API." }

        Write-Log -Message "Audit API authentication successful." -Level SUCCESS -Category Validation -Show
        return $response.data
    }
    catch {
        Write-Log -Message "Audit API authentication failed: $_" -Level ERROR -Category Validation -Show
        throw
    }
}

function Get-AuditUsers {
    <#
    .SYNOPSIS
        Retrieves the current user list from the audit API.
    .OUTPUTS
        Array of user objects: { matricula, conectado, … }
    #>
    $token = Connect-AuditAPI
    try {
        Write-Log -Message "Fetching user list from audit API..." -Level INFO -Category Status -Show

        $headers  = @{ Authorization = "Bearer $token" }
        $response = Invoke-RestMethod -Uri $ApiUrlUsers -Method Get -Headers $headers

        if (-not $response.data) { throw "No user data returned." }

        $auditData = [PSCustomObject]@{
            AuditTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TotalUsers     = $response.data.Count
            Users          = $response.data
        }
        $auditData | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempAuditFile

        Write-Log -Message "Retrieved $($response.data.Count) users from audit API." -Level SUCCESS -Category Status -Show
        return $response.data
    }
    catch {
        Write-Log -Message "Failed to retrieve users from audit API: $($_.Exception.Message)" -Level ERROR -Category Status -Show
        throw
    }
}
#endregion

#region ── Firewall helpers ────────────────────────────────────────────────────
function Test-FirewallConnectivity {
    $results = @()
    foreach ($fw in $script:FirewallAPIs) {
        try {
            $headers = @{ Authorization = "Bearer $($fw.Token)"; Accept = "application/json" }
            $null    = Invoke-RestMethod -Uri "$($fw.URL)/api/v2/monitor/system/status" -Method GET -Headers $headers -TimeoutSec 10
            Write-Log -Message "[$($fw.Name)] Connectivity OK" -Level SUCCESS -Category Firewall -Show
            $results += [PSCustomObject]@{ Name = $fw.Name; Status = "Online"; Error = $null }
        }
        catch {
            Write-Log -Message "[$($fw.Name)] Connectivity FAILED: $_" -Level ERROR -Category Firewall -Show
            $results += [PSCustomObject]@{ Name = $fw.Name; Status = "Offline"; Error = $_.Exception.Message }
        }
    }
    return $results
}
#endregion

#region ── AD helpers ──────────────────────────────────────────────────────────
function Get-UserNavigationGroups {
    <#
    .SYNOPSIS
        Queries AD for each user returned by the audit API and maps their current
        navigation group memberships (groups whose CN starts with $NavGroupPrefix).
    #>
    $auditUsers = Get-AuditUsers

    # Extract and normalise matriculas
    $matriculas = ($auditUsers | ForEach-Object {
        if ($_ -is [string]) { $_ }
        elseif ($_.PSObject.Properties.Name -contains 'matricula') { $_.matricula }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
      ForEach-Object { $_.ToString().Trim() } | Select-Object -Unique)

    if (-not $matriculas -or $matriculas.Count -eq 0) {
        Write-Log -Message "No user IDs received for validation." -Level WARNING -Category AD -Show
        return [pscustomobject]@{ Found = @(); NotFound = @() }
    }

    # LDAP special-character escaping
    function Escape-LdapValue {
        param([string]$s)
        $s = $s -replace '\\',  '\\5c'
        $s = $s -replace '\*',  '\\2a'
        $s = $s -replace '\(',  '\\28'
        $s = $s -replace '\)',  '\\29'
        $s = $s -replace '\x00','\\00'
        return $s
    }

    $orParts    = foreach ($m in $matriculas) { "(sAMAccountName=$(Escape-LdapValue $m))" }
    $ldapFilter = "(&(objectClass=user)(|$($orParts -join '')))"

    try {
        $adUsers = Get-ADUser -LDAPFilter $ldapFilter `
                              -SearchBase $ADSearchBase `
                              -Properties SamAccountName, Mail, DistinguishedName, MemberOf, Enabled `
                              -ErrorAction Stop

        $foundSAMs    = $adUsers | ForEach-Object { $_.SamAccountName }
        $notFoundSAMs = $matriculas | Where-Object { $_ -notin $foundSAMs }

        $results = foreach ($user in $adUsers) {

            $isExcluded     = $false
            $exclusionReason = ""

            if (-not $user.Enabled) {
                $isExcluded      = $true
                $exclusionReason = "Account DISABLED"
            }
            else {
                foreach ($ou in $ExcludedOUs) {
                    if ($user.DistinguishedName -like "*$ou") {
                        $isExcluded      = $true
                        $exclusionReason = "Excluded OU: $ou"
                        break
                    }
                }
            }

            $navGroups = @()
            if (-not $isExcluded) {
                foreach ($dn in ($user.MemberOf | Where-Object { $_ })) {
                    $match = [regex]::Match($dn, 'CN=([^,]+)')
                    if ($match.Success -and $match.Groups[1].Value -like "$NavGroupPrefix*") {
                        $navGroups += $match.Groups[1].Value
                    }
                }
                $navGroups = $navGroups | Select-Object -Unique
            }

            if ($isExcluded) {
                Write-Log -Message "User $($user.SamAccountName) EXCLUDED ($exclusionReason)" -Level WARNING -Category AD -Show
            }
            elseif ($navGroups.Count -gt 0) {
                Write-Log -Message "User $($user.SamAccountName) → navigation groups: $($navGroups -join ', ')" -Level SUCCESS -Category AD -Show
            }
            else {
                Write-Log -Message "User $($user.SamAccountName) → no navigation group found" -Level WARNING -Category AD -Show
            }

            [pscustomobject]@{
                UserId            = $user.SamAccountName
                Mail              = $user.Mail
                DistinguishedName = $user.DistinguishedName
                NavigationGroups  = $navGroups
                IsExcluded        = $isExcluded
                ExclusionReason   = $exclusionReason
            }
        }

        Write-Log -Message "AD lookup done: found=$($results.Count) | not-found=$($notFoundSAMs.Count)" -Level INFO -Category AD -Show
        return [pscustomobject]@{ Found = $results; NotFound = $notFoundSAMs }
    }
    catch {
        Write-Log -Message "AD query error: $($_.Exception.Message)" -Level ERROR -Category AD -Show
        throw
    }
}
#endregion

#region ── Classification & action planning ────────────────────────────────────
function Get-UserClassification {
    <#
    .SYNOPSIS
        Compares the current and previous audit snapshots, classifies each user by
        profile (Admin / Operator) and status (Connected / Disconnected), then builds
        an action plan (groups to add / remove) and a firewall deauth candidate list.
    #>
    $validated   = Get-UserNavigationGroups
    $currRoot    = Get-Content -LiteralPath $tempAuditFile -Raw | ConvertFrom-Json
    $prevRoot    = Get-Content -LiteralPath $auditFile     -Raw | ConvertFrom-Json
    $currentData = @($currRoot.Users)  | Where-Object { $_ -ne $null }
    $previousData= @($prevRoot.Users)  | Where-Object { $_ -ne $null }

    # Resolve group objects once
    $allGroups           = Get-ADGroup -SearchBase $GroupSearchBase -Filter *
    $grpAdminWhats       = $allGroups | Where-Object { $_.Name -eq $GroupNames.AdminWhats      }
    $grpOperatorWhats    = $allGroups | Where-Object { $_.Name -eq $GroupNames.OperatorWhats   }
    $grpAdminNoWhats     = $allGroups | Where-Object { $_.Name -eq $GroupNames.AdminNoWhats    }
    $grpOperatorNoWhats  = $allGroups | Where-Object { $_.Name -eq $GroupNames.OperatorNoWhats }

    foreach ($g in @(
        @{ Name = "AdminWhats";      Obj = $grpAdminWhats      }
        @{ Name = "OperatorWhats";   Obj = $grpOperatorWhats   }
        @{ Name = "AdminNoWhats";    Obj = $grpAdminNoWhats    }
        @{ Name = "OperatorNoWhats"; Obj = $grpOperatorNoWhats }
    )) {
        if (-not $g.Obj) {
            Write-Log -Message "Group '$($g.Name)' not found in '$GroupSearchBase'." -Level WARNING -Category Validation -Show
        }
    }

    # Build membership hash-tables for O(1) lookup
    $membAdminWhats      = @{}; if ($grpAdminWhats)      { Get-ADGroupMember -Identity $grpAdminWhats.DistinguishedName      | ForEach-Object { $membAdminWhats[$_.SamAccountName]      = $true } }
    $membOperatorWhats   = @{}; if ($grpOperatorWhats)   { Get-ADGroupMember -Identity $grpOperatorWhats.DistinguishedName   | ForEach-Object { $membOperatorWhats[$_.SamAccountName]   = $true } }
    $membAdminNoWhats    = @{}; if ($grpAdminNoWhats)    { Get-ADGroupMember -Identity $grpAdminNoWhats.DistinguishedName    | ForEach-Object { $membAdminNoWhats[$_.SamAccountName]    = $true } }
    $membOperatorNoWhats = @{}; if ($grpOperatorNoWhats) { Get-ADGroupMember -Identity $grpOperatorNoWhats.DistinguishedName | ForEach-Object { $membOperatorNoWhats[$_.SamAccountName] = $true } }

    # Index by user ID
    $currentByID  = @{}; foreach ($u in $currentData)  { $id = "$($u.matricula)".Trim(); if ($id) { $currentByID[$id]  = $u } }
    $previousByID = @{}; foreach ($u in $previousData) { $id = "$($u.matricula)".Trim(); if ($id) { $previousByID[$id] = $u } }

    # Users present in previous snapshot but absent from current (removed from audit tool)
    $missingFromCurrent = $previousData | Where-Object { -not $currentByID.ContainsKey("$($_.matricula)".Trim()) }

    $plan = @{
        Actions    = @{ ToAdd = @(); ToRemove = @() }
        DeauthPlan = @{ Candidates = @(); Ignored = @() }
        Excluded   = @()
    }

    foreach ($user in $validated.Found) {
        $id  = "$($user.UserId)".Trim()
        $dn  = "$($user.DistinguishedName)".Trim()
        $nav = @($user.NavigationGroups)

        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        # ── Profile detection ──
        $hasCompanyEmail = ($user.Mail -like "*$AdminEmailDomain")
        $inAdminExOU     = $false
        foreach ($suffix in $AdminExceptionOUSuffixes) {
            if ($dn -like "*$suffix") { $inAdminExOU = $true; break }
        }
        $isAdmin    = $hasCompanyEmail -or $inAdminExOU
        $isOperator = -not $isAdmin

        # ── Status detection ──
        $currentStatus  = if ($currentByID.ContainsKey($id))  { if ([bool]$currentByID[$id].conectado)  { "Connected" } else { "Disconnected" } } else { "Unknown" }
        $previousStatus = if ($previousByID.ContainsKey($id)) { if ([bool]$previousByID[$id].conectado) { "Connected" } else { "Disconnected" } } else { "Unknown" }

        # ── Current memberships ──
        $inAW  = $membAdminWhats.ContainsKey($id)
        $inOW  = $membOperatorWhats.ContainsKey($id)
        $inANW = $membAdminNoWhats.ContainsKey($id)
        $inONW = $membOperatorNoWhats.ContainsKey($id)

        $info = [PSCustomObject]@{
            UserId          = $id
            Mail            = $user.Mail
            IsAdmin         = $isAdmin
            IsOperator      = $isOperator
            CurrentStatus   = $currentStatus
            PreviousStatus  = $previousStatus
            IsExcluded      = [bool]$user.IsExcluded
            ExclusionReason = $user.ExclusionReason
        }

        # ── PRIORITY: excluded users → strip all groups + deauth ──
        if ($user.IsExcluded) {
            $plan.Excluded += $info
            Write-Log -Message "User $id EXCLUDED ($($user.ExclusionReason)) – removing from all groups." -Level WARNING -Category Validation -Show
            foreach ($pair in @(
                @{ In = $inAW;  Grp = $grpAdminWhats      }
                @{ In = $inOW;  Grp = $grpOperatorWhats   }
                @{ In = $inANW; Grp = $grpAdminNoWhats    }
                @{ In = $inONW; Grp = $grpOperatorNoWhats }
            )) {
                if ($pair.In -and $pair.Grp) {
                    $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $pair.Grp.Name; Reason = "EXCLUDED: $($user.ExclusionReason)" }
                }
            }
            $plan.DeauthPlan.Candidates += $info
            continue
        }

        # ── Deauth delta ──
        $nowConn  = ($currentStatus  -ieq "Connected")
        $nowDisc  = ($currentStatus  -ieq "Disconnected")
        $wasConn  = ($previousStatus -ieq "Connected")
        $wasDisc  = ($previousStatus -ieq "Disconnected")

        if (($nowConn -and $wasDisc) -or ($nowDisc -and $wasConn)) { $plan.DeauthPlan.Candidates += $info }
        elseif (($nowConn -and $wasConn) -or ($nowDisc -and $wasDisc)) { $plan.DeauthPlan.Ignored += $info }

        # ── Group assignment rules ──
        if ($nowConn) {
            if ($isAdmin) {
                if (-not $inAW  -and $grpAdminWhats)     { $plan.Actions.ToAdd    += [PSCustomObject]@{ UserId = $id; Group = $grpAdminWhats.Name;      Reason = "Connected – admin profile" } }
                if ($inOW       -and $grpOperatorWhats)  { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorWhats.Name;   Reason = "Admin profile – remove operator group" } }
                if ($inANW      -and $grpAdminNoWhats)   { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpAdminNoWhats.Name;    Reason = "Connected – remove NoWhats group" } }
                if ($inONW      -and $grpOperatorNoWhats){ $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorNoWhats.Name; Reason = "Connected – remove NoWhats group" } }
            }
            else {
                if (-not $inOW  -and $grpOperatorWhats)  { $plan.Actions.ToAdd    += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorWhats.Name;   Reason = "Connected – operator profile" } }
                if ($inAW       -and $grpAdminWhats)     { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpAdminWhats.Name;      Reason = "Operator profile – remove admin group" } }
                if ($inANW      -and $grpAdminNoWhats)   { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpAdminNoWhats.Name;    Reason = "Connected – remove NoWhats group" } }
                if ($inONW      -and $grpOperatorNoWhats){ $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorNoWhats.Name; Reason = "Connected – remove NoWhats group" } }
            }
        }
        elseif ($nowDisc) {
            if ($inAW  -and $grpAdminWhats)    { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpAdminWhats.Name;    Reason = "Disconnected – remove WhatsApp group" } }
            if ($inOW  -and $grpOperatorWhats) { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorWhats.Name; Reason = "Disconnected – remove WhatsApp group" } }

            if ($AssignNonWhatsOnDisconnect) {
                if ($isAdmin    -and -not $inANW -and $grpAdminNoWhats)    { $plan.Actions.ToAdd += [PSCustomObject]@{ UserId = $id; Group = $grpAdminNoWhats.Name;    Reason = "Disconnected – assign NoWhats (admin)" } }
                if ($isOperator -and -not $inONW -and $grpOperatorNoWhats) { $plan.Actions.ToAdd += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorNoWhats.Name; Reason = "Disconnected – assign NoWhats (operator)" } }
            }

            # Safety net: no group at all
            if (-not ($inAW -or $inOW -or $inANW -or $inONW)) {
                if ($isAdmin    -and $grpAdminNoWhats)    { $plan.Actions.ToAdd += [PSCustomObject]@{ UserId = $id; Group = $grpAdminNoWhats.Name;    Reason = "Disconnected – no group (safety net, admin)" } }
                elseif ($isOperator -and $grpOperatorNoWhats) { $plan.Actions.ToAdd += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorNoWhats.Name; Reason = "Disconnected – no group (safety net, operator)" } }
            }
        }
    }

    # ── Handle users removed from the audit tool ──
    Write-Log -Message "Processing $($missingFromCurrent.Count) users missing from current snapshot..." -Level INFO -Category Validation -Show
    foreach ($missing in $missingFromCurrent) {
        $id = "$($missing.matricula)".Trim()
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $inAW  = $membAdminWhats.ContainsKey($id)
        $inOW  = $membOperatorWhats.ContainsKey($id)
        $inANW = $membAdminNoWhats.ContainsKey($id)
        $inONW = $membOperatorNoWhats.ContainsKey($id)

        try {
            $adUser      = Get-ADUser -Identity $id -Properties Mail, DistinguishedName -ErrorAction Stop
            $isAdminMiss = ($adUser.Mail -like "*$AdminEmailDomain")
            foreach ($suffix in $AdminExceptionOUSuffixes) {
                if ($adUser.DistinguishedName -like "*$suffix") { $isAdminMiss = $true; break }
            }
        }
        catch {
            Write-Log -Message "MissingFromCurrent: $id not found in AD, skipping. Error: $($_.Exception.Message)" -Level WARNING -Category AD -Show
            continue
        }

        if ($inAW  -and $grpAdminWhats)    { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpAdminWhats.Name;    Reason = "Removed from audit tool" } }
        if ($inOW  -and $grpOperatorWhats) { $plan.Actions.ToRemove += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorWhats.Name; Reason = "Removed from audit tool" } }
        if ($isAdminMiss    -and -not $inANW -and $grpAdminNoWhats)    { $plan.Actions.ToAdd += [PSCustomObject]@{ UserId = $id; Group = $grpAdminNoWhats.Name;    Reason = "Removed from audit tool – move to NoWhats (admin)" } }
        elseif (-not $isAdminMiss -and -not $inONW -and $grpOperatorNoWhats) { $plan.Actions.ToAdd += [PSCustomObject]@{ UserId = $id; Group = $grpOperatorNoWhats.Name; Reason = "Removed from audit tool – move to NoWhats (operator)" } }
    }

    return $plan
}
#endregion

#region ── AD mutations ────────────────────────────────────────────────────────
function Set-ADGroupMembershipSafe {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$UserId,
        [string]$AddGroup    = "",
        [string]$RemoveGroup = ""
    )

    $results = @()
    foreach ($server in @($ADServer)) {
        $r = [PSCustomObject]@{ Server = $server; User = $UserId; AddedTo = $null; RemovedFrom = $null; Status = "OK"; Error = $null }
        try {
            $user        = Get-ADUser -Identity $UserId -Server $server -Properties memberOf -ErrorAction Stop
            $addGrpObj   = if ($AddGroup.Trim())    { Get-ADGroup -Identity $AddGroup    -Server $server -ErrorAction Stop } else { $null }
            $remGrpObj   = if ($RemoveGroup.Trim()) { Get-ADGroup -Identity $RemoveGroup -Server $server -ErrorAction Stop } else { $null }

            if ($addGrpObj -and ($user.memberOf -notcontains $addGrpObj.DistinguishedName)) {
                if ($PSCmdlet.ShouldProcess($UserId, "Add to '$($addGrpObj.Name)' on $server")) {
                    Add-ADGroupMember -Identity $addGrpObj.DistinguishedName -Members $user.DistinguishedName -Server $server -ErrorAction Stop
                    $r.AddedTo = $addGrpObj.Name
                    Write-Log -Message "[$UserId@$server] ADDED to '$($addGrpObj.Name)'" -Level SUCCESS -Category AD -Show
                }
            }
            if ($remGrpObj -and ($user.memberOf -contains $remGrpObj.DistinguishedName)) {
                if ($PSCmdlet.ShouldProcess($UserId, "Remove from '$($remGrpObj.Name)' on $server")) {
                    Remove-ADGroupMember -Identity $remGrpObj.DistinguishedName -Members $user.DistinguishedName -Server $server -Confirm:$false -ErrorAction Stop
                    $r.RemovedFrom = $remGrpObj.Name
                    Write-Log -Message "[$UserId@$server] REMOVED from '$($remGrpObj.Name)'" -Level SUCCESS -Category AD -Show
                }
            }
        }
        catch {
            $r.Status = "ERROR"; $r.Error = $_.Exception.Message
            Write-Log -Message "Error manipulating [$UserId] on '$server': $($_.Exception.Message)" -Level ERROR -Category AD -Show
        }
        $results += $r
    }
    return $results
}

function Update-WhatsAppAccess {
    param([Parameter(Mandatory)][object]$Plan)

    Write-Log -Message "Applying AD group changes..." -Level INFO -Category AD -Show
    $stats = @{ Updated = 0; Skipped = 0; Errors = 0 }
    $changed = [System.Collections.Generic.List[object]]::new()

    foreach ($action in $Plan.Actions.ToAdd) {
        $result = Set-ADGroupMembershipSafe -UserId $action.UserId -AddGroup $action.Group
        foreach ($r in $result) {
            if ($r.Status -eq 'ERROR') { $stats.Errors++; continue }
            if ($r.AddedTo) { $stats.Updated++; $changed.Add([PSCustomObject]@{ UserId = $action.UserId; Op = "ADD";    Group = $r.AddedTo;    Reason = $action.Reason }) }
            else            { $stats.Skipped++ }
        }
    }

    foreach ($action in $Plan.Actions.ToRemove) {
        $result = Set-ADGroupMembershipSafe -UserId $action.UserId -RemoveGroup $action.Group
        foreach ($r in $result) {
            if ($r.Status -eq 'ERROR') { $stats.Errors++; continue }
            if ($r.RemovedFrom) { $stats.Updated++; $changed.Add([PSCustomObject]@{ UserId = $action.UserId; Op = "REMOVE"; Group = $r.RemovedFrom; Reason = $action.Reason }) }
            else                { $stats.Skipped++ }
        }
    }

    $summary = "Updated: $($stats.Updated) | Already correct: $($stats.Skipped) | Errors: $($stats.Errors)"
    Write-Log -Message $summary -Level SUCCESS -Category AD     -Show
    Write-Log -Message $summary -Level SUCCESS -Category Status -Show

    if ($changed.Count -gt 0) {
        $table = ($changed | Format-Table UserId, Op, Group, Reason -Wrap | Out-String -Width 4096).Trim()
        Write-Log -Message "`n$table" -Level INFO -Category AD     -Show
        Write-Log -Message "`n$table" -Level INFO -Category Status
    }
}
#endregion

#region ── Firewall deauth ─────────────────────────────────────────────────────
function Get-FirewallSessions {
    param(
        [string]$FirewallURL,
        [string]$Token,
        [string]$SiteName,
        [object]$Plan
    )

    $headers = @{ Authorization = "Bearer $Token"; Accept = "application/json" }
    $apiUrl  = "$FirewallURL/api/v2/monitor/user/firewall?vdom=root&action=schema"

    try {
        Write-Log -Message "[$SiteName] Collecting active sessions..." -Level INFO -Category Firewall -Show
        $sessions = (Invoke-RestMethod -Uri $apiUrl -Method GET -Headers $headers).results

        foreach ($candidate in $Plan.DeauthPlan.Candidates) {
            $id       = $candidate.UserId
            $userSess = $sessions | Where-Object { $_.username -eq $id }

            foreach ($s in $userSess) {
                Write-Log -Message "[$SiteName] $id connected at $($s.ipaddr)" -Level INFO -Category Firewall -Show
                $s | Select-Object *, `
                    @{ Name = "Site";         Expression = { $SiteName } }, `
                    @{ Name = "FirewallURL";  Expression = { $FirewallURL } }, `
                    @{ Name = "FirewallToken";Expression = { $Token } } |
                    ForEach-Object { $script:AllSessions += $_ }
            }
            if (-not $userSess) {
                Write-Log -Message "[$SiteName] $id – no active session found." -Level INFO -Category Firewall
            }
        }
        Write-Log -Message "[$SiteName] Sessions collected: $($userSess.Count)" -Level SUCCESS -Category Firewall
    }
    catch {
        Write-Log -Message "[$SiteName] Failed to collect sessions: $($_.Exception.Message)" -Level ERROR -Category Firewall -Show
    }
}

function Invoke-FirewallDeauth {
    param(
        [string]$FirewallURL,
        [string]$Token,
        [string]$SiteName,
        [array] $Sessions
    )

    if ($Sessions.Count -eq 0) {
        Write-Log -Message "[$SiteName] No sessions to deauthenticate." -Level WARNING -Category Firewall -Show
        return
    }

    $logoutUrl = "$FirewallURL/api/v2/monitor/user/firewall/deauth?vdom=root"
    $headers   = @{ Authorization = "Bearer $Token"; Accept = "application/json" }
    $ok = 0; $err = 0

    foreach ($s in $Sessions) {
        try {
            $body = @{ ip = $s.ipaddr; user_type = "firewall"; id = 0; ip_version = "ip4"; method = $s.method; username = $s.username } | ConvertTo-Json
            Invoke-RestMethod -Uri $logoutUrl -Method POST -Headers $headers -Body $body -ContentType "application/json"
            Write-Log -Message "[$SiteName] Deauthenticated $($s.username) ($($s.ipaddr))" -Level SUCCESS -Category Firewall -Show
            $ok++
            Start-Sleep -Milliseconds 200
        }
        catch {
            Write-Log -Message "[$SiteName] Failed to deauthenticate $($s.username): $($_.Exception.Message)" -Level ERROR -Category Firewall -Show
            $err++
        }
    }

    $msg = "[$SiteName] Deauth complete – success: $ok | errors: $err"
    Write-Log -Message $msg -Level INFO -Category Firewall -Show
    Write-Log -Message $msg -Level INFO -Category Status
}

function Invoke-AllFirewallDeauth {
    param([Parameter(Mandatory)][object]$Plan)

    Write-Log -Message "Starting firewall deauth across all sites..." -Level INFO -Category Firewall -Show
    $script:AllSessions = @()

    foreach ($fw in $script:FirewallAPIs) {
        $headers = @{ Authorization = "Bearer $($fw.Token)"; Accept = "application/json" }
        try {
            $null = Invoke-RestMethod -Uri "$($fw.URL)/api/v2/monitor/system/status" -Method GET -Headers $headers -TimeoutSec 10
            Get-FirewallSessions -FirewallURL $fw.URL -Token $fw.Token -SiteName $fw.Name -Plan $Plan
        }
        catch {
            Write-Log -Message "[$($fw.Name)] Auth failed, skipping: $($_.Exception.Message)" -Level ERROR -Category Firewall -Show
        }
    }

    foreach ($fw in $script:FirewallAPIs) {
        $siteSessions = $script:AllSessions | Where-Object { $_.Site -eq $fw.Name }
        Invoke-FirewallDeauth -FirewallURL $fw.URL -Token $fw.Token -SiteName $fw.Name -Sessions $siteSessions
    }

    Write-Log -Message "All deauth operations complete. Total sessions processed: $($script:AllSessions.Count)" -Level SUCCESS -Category Firewall -Show
}
#endregion

#region ── Audit file rotation ─────────────────────────────────────────────────
function Update-AuditFile {
    Write-Log -Message "Rotating audit file..." -Level INFO -Category Validation

    if (Test-Path $tempAuditFile) {
        if (Test-Path $auditFile) { Remove-Item $auditFile -Force }
        Move-Item -Path $tempAuditFile -Destination $auditFile -Force
        Write-Log -Message "Audit file updated: $auditFile" -Level SUCCESS -Category Validation -Show
    }
    else {
        Write-Log -Message "Temp audit file not found – audit file not rotated." -Level WARNING -Category Validation -Show
    }
}
#endregion

#region ── Entry point ─────────────────────────────────────────────────────────
Start-Transcript -Path $logGeneral

# Load credentials and build runtime FirewallAPIs array
$script:Creds = Get-DecryptedCredentials
$script:FirewallAPIs = $FirewallSites | ForEach-Object {
    @{
        Name  = $_.Name
        URL   = $_.URL
        Token = $script:Creds.FirewallTokens[$_.Name]
    }
}

# First-run bootstrap: if no previous audit exists, create an empty one
if (-not (Test-Path $auditFile)) {
    Write-Log -Message "No previous audit file found – creating empty baseline." -Level WARNING -Category Validation -Show
    [PSCustomObject]@{ AuditTimestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); TotalUsers = 0; Users = @() } |
        ConvertTo-Json -Depth 10 | Out-File -FilePath $auditFile
}

Initialize-ScriptEnvironment
Test-FirewallConnectivity

$classification = Get-UserClassification
Update-WhatsAppAccess      -Plan $classification
Invoke-AllFirewallDeauth   -Plan $classification
Update-AuditFile

Write-Log -Message "=== EXECUTION COMPLETED SUCCESSFULLY ===" -Level SUCCESS -Category Validation -Show
Stop-Transcript
#endregion
