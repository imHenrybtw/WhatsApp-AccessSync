<#
.SYNOPSIS
    Interactively encrypts and saves API and FortiGate credentials to disk.

.DESCRIPTION
    Generates a random AES-256 key (aes.key) and encrypts all provided credentials
    into credentials.json. Both files are written to the same directory as this script.

    Run this once per environment (or whenever credentials change).
    Keep aes.key in a secure location — loss of the key means re-running this script.

.NOTES
    Author  : Henry Victor Passold Gomes
    License : GNU General Public License v3.0
#>

$scriptDir       = Split-Path -Parent $MyInvocation.MyCommand.Path
$credentialsPath = Join-Path $scriptDir "..\credentials.json"
$keyPath         = Join-Path $scriptDir "..\aes.key"

Write-Host "=== Credential Setup ===" -ForegroundColor Cyan
Write-Host "Credentials will be saved to: $credentialsPath"
Write-Host "AES key will be saved to     : $keyPath"
Write-Host ""

# Generate AES-256 key
$aesKey = New-Object byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)
[System.IO.File]::WriteAllBytes($keyPath, $aesKey)
Write-Host "AES key generated." -ForegroundColor Green

function Encrypt-Value {
    param([string]$PlainText)
    $secure = ConvertTo-SecureString $PlainText -AsPlainText -Force
    return ConvertFrom-SecureString $secure -Key $aesKey
}

# ── Audit API credentials ──
Write-Host ""
Write-Host "── Audit API ──" -ForegroundColor Yellow
$apiKey    = Read-Host "API Key (username / client_id)"
$apiSecret = Read-Host "API Secret (password / client_secret)"

# ── FortiGate tokens ──
Write-Host ""
Write-Host "── FortiGate API Tokens ──" -ForegroundColor Yellow
Write-Host "Enter one token per site. Leave blank to finish."

$firewallTokens = @{}
while ($true) {
    $siteName = Read-Host "Site name (e.g. HQ, Branch01) — or press Enter to finish"
    if ([string]::IsNullOrWhiteSpace($siteName)) { break }
    $token = Read-Host "API token for $siteName"
    $firewallTokens[$siteName] = Encrypt-Value $token
}

# ── Build and save JSON ──
$encrypted = [PSCustomObject]@{
    ApiKey         = Encrypt-Value $apiKey
    ApiSecret      = Encrypt-Value $apiSecret
    FirewallTokens = $firewallTokens
}

$encrypted | ConvertTo-Json -Depth 5 | Out-File -FilePath $credentialsPath -Encoding UTF8
Write-Host ""
Write-Host "Credentials saved successfully." -ForegroundColor Green
Write-Host "IMPORTANT: Keep aes.key secure. Do NOT commit either file to source control." -ForegroundColor Red
