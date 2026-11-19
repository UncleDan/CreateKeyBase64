<#
.SYNOPSIS
    Creates (or reuses) an Android keystore and encodes it as Base64 for GitHub Actions.

.DESCRIPTION
    GitHub Actions secrets can only hold text, so a binary keystore (.jks / .keystore)
    must be stored as a Base64 string and decoded again inside the workflow.

    This script:
      1. Uses an existing keystore, or generates a new one with keytool (-Generate).
      2. Encodes the keystore as a single-line Base64 string (no line breaks).
      3. Writes the string to a text file and, optionally, copies it to the clipboard.
      4. Optionally uploads all signing secrets to a GitHub repository with the gh CLI.

    Works with Windows PowerShell 5.1 and PowerShell 7+ (Windows, macOS, Linux).

.PARAMETER KeystorePath
    Path of the keystore to encode (or to create when -Generate is used).

.PARAMETER Generate
    Generate a new keystore with keytool instead of using an existing one.

.PARAMETER Alias
    Key alias. Required with -Generate; also used for the printed secret summary.

.PARAMETER OutputFile
    File where the Base64 string is written. Defaults to "<keystore>.base64.txt".

.PARAMETER ValidityDays
    Key validity in days when generating (default 10000, ~27 years; Google Play
    requires validity beyond 22 October 2033).

.PARAMETER DName
    Distinguished name for the certificate, e.g. "CN=John Doe, O=Example, C=US".
    If omitted with -Generate, you are prompted for the fields.

.PARAMETER CopyToClipboard
    Copy the Base64 string to the clipboard.

.PARAMETER GitHubRepo
    "owner/repo". If set, the secrets are uploaded with "gh secret set"
    (requires the GitHub CLI, authenticated with "gh auth login").

.PARAMETER SecretPrefix
    Prefix for the secret names (default "ANDROID").

.EXAMPLE
    ./New-KeystoreBase64.ps1 -KeystorePath .\release.jks -Generate -Alias upload -CopyToClipboard

.EXAMPLE
    ./New-KeystoreBase64.ps1 -KeystorePath .\existing.keystore -Alias mykey

.EXAMPLE
    ./New-KeystoreBase64.ps1 -KeystorePath .\release.jks -Alias upload -GitHubRepo myuser/myapp
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$KeystorePath,

    [switch]$Generate,

    [string]$Alias,

    [string]$OutputFile,

    [ValidateRange(1, 36500)]
    [int]$ValidityDays = 10000,

    [string]$DName,

    [switch]$CopyToClipboard,

    [ValidatePattern('^[\w.-]+/[\w.-]+$')]
    [string]$GitHubRepo,

    [string]$SecretPrefix = 'ANDROID'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-PlainText([Security.SecureString]$Secure) {
    return [System.Net.NetworkCredential]::new('', $Secure).Password
}

function Read-Password([string]$Prompt, [int]$MinLength = 6) {
    while ($true) {
        $first = ConvertTo-PlainText (Read-Host -Prompt $Prompt -AsSecureString)
        if ($first.Length -lt $MinLength) {
            Write-Warning "The password must be at least $MinLength characters long."
            continue
        }
        $second = ConvertTo-PlainText (Read-Host -Prompt "$Prompt (confirm)" -AsSecureString)
        if ($first -ceq $second) { return $first }
        Write-Warning 'The passwords do not match, try again.'
    }
}

function Find-Keytool {
    $exe = if ($IsWindows -or $env:OS -eq 'Windows_NT') { 'keytool.exe' } else { 'keytool' }
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += Join-Path (Join-Path $env:JAVA_HOME 'bin') $exe }
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    # Android Studio bundled JDK (Windows default locations)
    foreach ($dir in @("$env:ProgramFiles\Android\Android Studio\jbr\bin",
                       "$env:ProgramFiles\Android\Android Studio\jre\bin")) {
        if ($env:ProgramFiles) { $candidates += Join-Path $dir $exe }
    }
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    throw 'keytool not found. Install a JDK (or Android Studio) and set JAVA_HOME, or add keytool to PATH.'
}

$KeystorePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($KeystorePath)
$storePassword = $null

# --- 1. Generate the keystore if requested -----------------------------------
if ($Generate) {
    if (Test-Path $KeystorePath) {
        throw "'$KeystorePath' already exists. Remove it or omit -Generate to encode it."
    }
    if (-not $Alias) { $Alias = Read-Host 'Key alias (e.g. upload)' }
    if (-not $Alias) { throw 'An alias is required.' }

    if (-not $DName) {
        Write-Host 'Certificate details (press Enter to skip a field):' -ForegroundColor Cyan
        $fields = [ordered]@{
            CN = 'First and last name'
            OU = 'Organizational unit'
            O  = 'Organization'
            L  = 'City or locality'
            ST = 'State or province'
            C  = 'Two-letter country code'
        }
        $parts = foreach ($key in $fields.Keys) {
            $value = Read-Host "  $($fields[$key])"
            if ($value) { "$key=$($value -replace ',', '\,')" }
        }
        if (-not $parts) { throw 'At least one certificate field is required.' }
        $DName = $parts -join ', '
    }

    # Modern keytool creates PKCS12 keystores, where the key password must equal
    # the store password, so a single password is used for both.
    $storePassword = Read-Password 'Keystore password'

    $keytool = Find-Keytool
    $dir = Split-Path -Parent $KeystorePath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

    Write-Host "Generating keystore with $keytool ..." -ForegroundColor Cyan
    & $keytool -genkeypair -v `
        -keystore $KeystorePath `
        -storetype PKCS12 `
        -alias $Alias `
        -keyalg RSA -keysize 2048 `
        -validity $ValidityDays `
        -dname $DName `
        -storepass $storePassword `
        -keypass $storePassword
    if ($LASTEXITCODE -ne 0) { throw "keytool failed with exit code $LASTEXITCODE." }
}

if (-not (Test-Path $KeystorePath -PathType Leaf)) {
    throw "Keystore not found: '$KeystorePath'. Use -Generate to create a new one."
}

# --- 2. Encode as single-line Base64 -----------------------------------------
$bytes  = [System.IO.File]::ReadAllBytes($KeystorePath)
$base64 = [System.Convert]::ToBase64String($bytes)

if (-not $OutputFile) { $OutputFile = "$KeystorePath.base64.txt" }
$OutputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
# Write without BOM and without a trailing newline.
[System.IO.File]::WriteAllText($OutputFile, $base64, [System.Text.UTF8Encoding]::new($false))

# Sanity check: decoding must give back the exact same bytes.
$roundTrip = [System.Convert]::FromBase64String([System.IO.File]::ReadAllText($OutputFile))
if ([System.Convert]::ToBase64String($roundTrip) -ne $base64 -or $roundTrip.Length -ne $bytes.Length) {
    throw 'Base64 round-trip verification failed.'
}

Write-Host ''
Write-Host "Keystore : $KeystorePath ($($bytes.Length) bytes)" -ForegroundColor Green
Write-Host "Base64   : $OutputFile ($($base64.Length) chars)" -ForegroundColor Green

# --- 3. Clipboard -------------------------------------------------------------
if ($CopyToClipboard) {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
        Set-Clipboard -Value $base64
        Write-Host 'Base64 string copied to the clipboard.' -ForegroundColor Green
    } else {
        Write-Warning 'Set-Clipboard is not available on this system; copy the string from the output file.'
    }
}

# --- 4. Secrets ---------------------------------------------------------------
$names = [ordered]@{
    Keystore      = "${SecretPrefix}_KEYSTORE_BASE64"
    StorePassword = "${SecretPrefix}_KEYSTORE_PASSWORD"
    Alias         = "${SecretPrefix}_KEY_ALIAS"
    KeyPassword   = "${SecretPrefix}_KEY_PASSWORD"
}

if ($GitHubRepo) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'GitHub CLI (gh) not found. Install it from https://cli.github.com and run "gh auth login".'
    }
    if (-not $Alias) { $Alias = Read-Host 'Key alias' }
    if (-not $storePassword) { $storePassword = ConvertTo-PlainText (Read-Host 'Keystore password' -AsSecureString) }
    $keyPassword = ConvertTo-PlainText (Read-Host 'Key password (press Enter if same as keystore password)' -AsSecureString)
    if (-not $keyPassword) { $keyPassword = $storePassword }

    $values = @{
        $names.Keystore      = $base64
        $names.StorePassword = $storePassword
        $names.Alias         = $Alias
        $names.KeyPassword   = $keyPassword
    }
    foreach ($name in $names.Values) {
        # Values are piped through stdin so they never appear on the command line.
        $values[$name] | gh secret set $name --repo $GitHubRepo
        if ($LASTEXITCODE -ne 0) { throw "Failed to set secret $name on $GitHubRepo." }
        Write-Host "Secret $name set on $GitHubRepo." -ForegroundColor Green
    }
} else {
    Write-Host ''
    Write-Host 'Add these secrets in GitHub: Settings > Secrets and variables > Actions' -ForegroundColor Cyan
    Write-Host "  $($names.Keystore)  = contents of $OutputFile"
    Write-Host "  $($names.StorePassword)  = keystore password"
    Write-Host "  $($names.Alias)  = $(if ($Alias) { $Alias } else { '<your key alias>' })"
    Write-Host "  $($names.KeyPassword)  = key password"
}

Write-Host ''
Write-Warning "Keep '$KeystorePath' and its passwords safe and backed up, and never commit them. Delete '$OutputFile' once the secret is saved."
