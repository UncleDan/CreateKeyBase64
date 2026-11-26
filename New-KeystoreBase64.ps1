# New-KeystoreBase64.ps1 by Daniele Lolli (UncleDan) feat. Claude AI - Release 1.2 - 2026-11-22 14-43-14
<#
.SYNOPSIS
    Creates (or reuses) an Android signing keystore and prepares the GitHub Actions secrets.

.DESCRIPTION
    GitHub Actions secrets can only hold text, so the binary keystore is stored as a
    single-line Base64 string and decoded again inside the workflow.

    The script:
      1. Uses an existing keystore, or generates a new PKCS12 one with keytool.
         If keytool is not installed it can download a portable Temurin JRE (Windows x64),
         use it and delete it afterwards.
      2. Writes a TXT file with every secret (name and value) ready to copy and paste
         into GitHub: KEYSTORE_BASE64, KEYSTORE_PASSWORD, KEY_ALIAS, KEY_PASSWORD,
         plus the certificate fingerprints (SHA1/SHA256).
      3. Optionally uploads the secrets with the GitHub CLI (gh).

    Every parameter is optional: anything required that is missing is asked for.
    Run with no parameters for a fully guided mode, or with -Help for a parameter summary.

    Works with Windows PowerShell 5.1 and PowerShell 7+ (Windows, macOS, Linux).

.PARAMETER KeystorePath
    Keystore to encode, or to create with -Generate. Prompted if missing.

.PARAMETER Generate
    Generate a new keystore. Also offered automatically when the file does not exist.

.PARAMETER Alias
    Key alias (secret KEY_ALIAS). Prompted if missing.

.PARAMETER DName
    Certificate owner, e.g. "CN=John Doe, O=Example, C=US". Prompted field by field if missing.

.PARAMETER GeneratePassword
    Only with a new keystore: generate a random password instead of typing it.
    It is shown once at the end and written to the TXT file: save it in a password manager.
    In guided mode it is offered (default: yes).

.PARAMETER PasswordLength
    Length of the generated password, 16-128 (default 32). The password always contains
    digits, uppercase and lowercase letters and the special characters - _ . + : @ /
    which need no quoting or escaping in CMD/DOS, PowerShell, Bash/sh or MySQL;
    it never starts with a special character.

.PARAMETER KeySize
    RSA key size when generating: 2048, 3072 or 4096 (default 4096).

.PARAMETER ValidityDays
    Certificate validity when generating (default 10000 days, about 27 years;
    Google Play requires validity beyond 22 October 2033).

.PARAMETER SecretPrefix
    Optional prefix for the secret names. Empty by default (KEYSTORE_BASE64, ...).
    "MYAPP" gives MYAPP_KEYSTORE_BASE64, MYAPP_KEY_ALIAS, ...

.PARAMETER OutputFile
    TXT file with the secrets. Default: next to the keystore, "<name>.github-secrets.txt".

.PARAMETER GitHubRepo
    "owner/repo". If set, the secrets are uploaded with "gh secret set".

.PARAMETER CopyToClipboard
    Also copy the Base64 string to the clipboard.

.PARAMETER Help
    Show a short summary of the parameters and exit.

.EXAMPLE
    ./New-KeystoreBase64.ps1

    Guided mode: asks for everything.

.EXAMPLE
    ./New-KeystoreBase64.ps1 -KeystorePath .\myapp.p12 -Generate -Alias myapp -DName "CN=John Doe, C=US"

.EXAMPLE
    ./New-KeystoreBase64.ps1 -KeystorePath .\existing.jks -Alias upload -SecretPrefix MYAPP -GitHubRepo myuser/myapp

.EXAMPLE
    ./New-KeystoreBase64.ps1 -KeystorePath .\myapp.p12 -Generate -Alias myapp -DName "CN=John Doe, C=US" -GeneratePassword

    New keystore with a random 32-character password.
#>
[CmdletBinding()]
param(
    [string]$KeystorePath,

    [switch]$Generate,

    [string]$Alias,

    [string]$DName,

    [switch]$GeneratePassword,

    [ValidateRange(16, 128)]
    [int]$PasswordLength = 32,

    [ValidateSet(2048, 3072, 4096)]
    [int]$KeySize = 4096,

    [ValidateRange(1, 36500)]
    [int]$ValidityDays = 10000,

    [ValidatePattern('^([A-Za-z_][A-Za-z0-9_]*)?$')]
    [string]$SecretPrefix = '',

    [string]$OutputFile,

    [ValidatePattern('^[\w.-]+/[\w.-]+$')]
    [string]$GitHubRepo,

    [switch]$CopyToClipboard,

    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # much faster downloads in Windows PowerShell 5.1

# --- Help ---------------------------------------------------------------------
if ($Help) {
    $me = Split-Path -Leaf $PSCommandPath
    Write-Host @"
$me - create an Android keystore and prepare the GitHub Actions secrets

Usage:  ./$me [parameters]      (no parameters = guided mode, every value is asked)

Parameters (all optional):
  -KeystorePath <file>    Keystore to encode or to create (.p12, .jks, .keystore)
  -Generate               Create a new keystore (offered anyway if the file is missing)
  -Alias <name>           Key alias, goes into KEY_ALIAS
  -DName "<dn>"           Certificate owner, e.g. "CN=John Doe, O=Example, L=Rome, C=IT"
  -GeneratePassword       New keystore only: random password instead of typing it
  -PasswordLength <n>     Length of the generated password, 16-128  (default 32)
  -KeySize <n>            2048 | 3072 | 4096                       (default 4096)
  -ValidityDays <n>       Certificate validity in days            (default 10000)
  -SecretPrefix <text>    Prefix for secret names: MYAPP -> MYAPP_KEYSTORE_BASE64
                                                                   (default: none)
  -OutputFile <file>      TXT with all secrets   (default <keystore>.github-secrets.txt)
  -GitHubRepo owner/repo  Upload the secrets with the GitHub CLI (gh)
  -CopyToClipboard        Also copy the Base64 string to the clipboard
  -Help, -h               Show this help

Secrets produced (with the optional prefix):
  KEYSTORE_BASE64  KEYSTORE_PASSWORD  KEY_ALIAS  KEY_PASSWORD

Examples:
  ./$me
  ./$me -KeystorePath .\myapp.p12 -Generate -Alias myapp -DName "CN=John Doe, C=IT"
  ./$me -KeystorePath .\myapp.p12 -Generate -Alias myapp -DName "CN=John Doe, C=IT" -GeneratePassword
  ./$me -KeystorePath .\old.jks -Alias upload -SecretPrefix MYAPP -GitHubRepo myuser/myapp

Full help:  Get-Help ./$me -Detailed
"@
    return
}

# --- Helpers ------------------------------------------------------------------
function ConvertTo-PlainText([Security.SecureString]$Secure) {
    return [System.Net.NetworkCredential]::new('', $Secure).Password
}

function Write-Help([string[]]$Lines) {
    Write-Host ''
    foreach ($line in $Lines) { if ($line) { Write-Host "  $line" -ForegroundColor DarkGray } }
}

function Read-Password([string]$Prompt, [string[]]$Help, [switch]$Confirm, [int]$MinLength = 8) {
    Write-Help $Help
    while ($true) {
        $first = ConvertTo-PlainText (Read-Host -Prompt $Prompt -AsSecureString)
        if (-not $first) { Write-Warning 'A password is required.'; continue }
        if (-not $Confirm) { return $first }
        if ($first.Length -lt $MinLength) {
            Write-Warning "The password must be at least $MinLength characters long."
            continue
        }
        $second = ConvertTo-PlainText (Read-Host -Prompt "$Prompt (repeat)" -AsSecureString)
        if ($first -ceq $second) { return $first }
        Write-Warning 'The passwords do not match, try again.'
    }
}

function Read-Value([string]$Prompt, [string[]]$Help, [string]$Default, [switch]$Optional) {
    Write-Help $Help
    $label = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
    while ($true) {
        $value = (Read-Host -Prompt $label).Trim()
        if (-not $value) { $value = $Default }
        if ($value -or $Optional) { return $value }
        Write-Warning 'A value is required.'
    }
}

function Read-YesNo([string]$Prompt, [string[]]$Help, [bool]$Default = $true) {
    Write-Help $Help
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $answer = (Read-Host -Prompt "$Prompt [$hint]").Trim()
        if (-not $answer) { return $Default }
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$') { return $false }
        Write-Warning 'Please answer y or n.'
    }
}

function Test-IsWindows { return ($env:OS -eq 'Windows_NT') }

# Random password from a cryptographic generator (works in Windows PowerShell 5.1 too).
# Special characters are limited to  - _ . + : @ /  because they have no special meaning in
# CMD/DOS (& | < > ^ % ! ( ) , ; = are), PowerShell ($ ` ' " # { } ; and @ at the start), Bash/sh
# ($ ` \ ' " ! * ? [ ] { } ~ # & | ; < >) or MySQL string literals (' " \ `).
# No kind of quote or apostrophe is ever used.
# At least one digit, uppercase, lowercase and special character; the first character
# is always a letter, so the password never looks like an option (-x, /x, +x).
function New-RandomPassword([int]$Length = 32) {
    $upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lower   = 'abcdefghijklmnopqrstuvwxyz'
    $digits  = '0123456789'
    $special = '-_.+:@/'
    $all     = $upper + $lower + $digits + $special
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $buffer = New-Object byte[] 4
        # uniform index in [0, n): rejection sampling, no modulo bias
        $next = {
            param([int]$n)
            $limit = [uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$n)
            do { $rng.GetBytes($buffer); $v = [BitConverter]::ToUInt32($buffer, 0) } while ($v -ge $limit)
            return [int]($v % [uint32]$n)
        }
        $pick = { param([string]$set) $set[(& $next $set.Length)] }

        $chars = New-Object System.Collections.Generic.List[char]
        $chars.Add((& $pick $digits)); $chars.Add((& $pick $special))
        $chars.Add((& $pick $upper));  $chars.Add((& $pick $lower))
        while ($chars.Count -lt $Length - 1) { $chars.Add((& $pick $all)) }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {          # Fisher-Yates shuffle
            $j = & $next ($i + 1)
            $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t
        }
        $first = & $pick ($upper + $lower)                     # always starts with a letter
        return ([string]$first) + (-join $chars)
    }
    finally { $rng.Dispose() }
}

function ConvertTo-SecretPrefix([string]$Prefix) {
    if (-not $Prefix) { return '' }
    $Prefix = $Prefix.ToUpperInvariant()
    if (-not $Prefix.EndsWith('_')) { $Prefix += '_' }
    if ($Prefix -like 'GITHUB_*') { throw 'Secret names cannot start with GITHUB_.' }
    return $Prefix
}

function Find-Keytool {
    $exe = if (Test-IsWindows) { 'keytool.exe' } else { 'keytool' }
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += Join-Path (Join-Path $env:JAVA_HOME 'bin') $exe }
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    if (Test-IsWindows) {
        # Android Studio bundled JDK
        $candidates += "$env:ProgramFiles\Android\Android Studio\jbr\bin\keytool.exe"
        $candidates += "$env:ProgramFiles\Android\Android Studio\jre\bin\keytool.exe"
        $candidates += "$env:LOCALAPPDATA\Programs\Android Studio\jbr\bin\keytool.exe"
    } else {
        $candidates += '/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/keytool'
    }
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    if (Test-IsWindows) {
        foreach ($root in "$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Microsoft",
                          "$env:ProgramFiles\Java", "$env:ProgramFiles\Zulu") {
            if (Test-Path $root) {
                $k = Get-ChildItem $root -Recurse -Filter keytool.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($k) { return $k.FullName }
            }
        }
    }
    return $null
}

function Get-PortableKeytool([string]$Destination) {
    Write-Host 'Downloading a portable Temurin 17 JRE (~45 MB)...' -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = 'https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse'
    $zip = Join-Path $Destination 'jre.zip'
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $Destination -Force
    $k = Get-ChildItem $Destination -Recurse -Filter keytool.exe | Select-Object -First 1
    if (-not $k) { throw 'keytool.exe not found in the downloaded JRE.' }
    return $k.FullName
}

function Get-SecretNames([string]$Prefix) {
    return [ordered]@{
        Keystore      = "${Prefix}KEYSTORE_BASE64"
        StorePassword = "${Prefix}KEYSTORE_PASSWORD"
        Alias         = "${Prefix}KEY_ALIAS"
        KeyPassword   = "${Prefix}KEY_PASSWORD"
    }
}

$names = Get-SecretNames (ConvertTo-SecretPrefix $SecretPrefix)

# --- 0. Ask for anything that was not supplied ------------------------------
$wizard = $PSBoundParameters.Count -eq 0

if ($wizard) {
    while ($true) {
        $prefix = Read-Value 'Secret name prefix' -Optional -Help @(
            'Optional, useful when one repository holds several keystores. Press Enter for none.',
            'Example: MYAPP  ->  MYAPP_KEYSTORE_BASE64, MYAPP_KEY_ALIAS, ...',
            "Without a prefix: $($names.Values -join ', ')"
        )
        if (-not $prefix -or $prefix -match '^[A-Za-z_][A-Za-z0-9_]*$') { break }
        Write-Warning 'Use only letters, digits and underscores, not starting with a digit.'
    }
    $names = Get-SecretNames (ConvertTo-SecretPrefix $prefix)
}

if (-not $KeystorePath) {
    $KeystorePath = Read-Value 'Keystore file path' -Default (Join-Path (Get-Location) 'release.p12') -Help @(
        'The signing keystore: an existing file to encode (.p12, .jks, .keystore), or where to create a new one.',
        'Example: C:\keys\myapp-release.p12',
        "Its Base64 content goes into the secret $($names.Keystore)."
    )
}
$KeystorePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($KeystorePath)

if ($Generate -and (Test-Path $KeystorePath)) {
    throw "'$KeystorePath' already exists: it will not be overwritten (losing it prevents app updates)."
}
if (-not $Generate -and -not (Test-Path $KeystorePath -PathType Leaf)) {
    if (Read-YesNo 'Generate a new keystore?' -Help @(
            "'$KeystorePath' does not exist.",
            'Answer y to create a new signing key there, n to stop.'
        )) {
        $Generate = $true
    } else {
        throw "Keystore not found: '$KeystorePath'."
    }
}

if (-not $Alias) {
    $aliasHelp = if ($Generate) {
        @('Name of the key inside the new keystore: short, lowercase, no spaces.',
          'Example: myapp')
    } else {
        @('Name of the key inside the existing keystore (the alias chosen when it was created).',
          'To see it: keytool -list -keystore <file>')
    }
    $Alias = Read-Value 'Key alias' -Default $(if ($Generate) { 'upload' } else { '' }) -Help (
        $aliasHelp + "Goes into the secret $($names.Alias)."
    )
}

if ($Generate -and -not $DName) {
    Write-Help @(
        'Certificate owner. NOT secret: stored in the certificate and readable by anyone who opens the APK.',
        'Press Enter to skip a field (at least one is required).'
    )
    $fields = [ordered]@{
        CN = 'Name of the developer or company, e.g. John Doe'
        OU = 'Organizational unit, e.g. Mobile'
        O  = 'Organization, e.g. Example Ltd'
        L  = 'City, e.g. Rome'
        ST = 'State or province, e.g. RM'
        C  = 'Two-letter country code, e.g. IT'
    }
    $parts = foreach ($key in $fields.Keys) {
        $value = (Read-Host "  $key - $($fields[$key])").Trim()
        if ($value) { "$key=$($value -replace ',', '\,')" }
    }
    if (-not $parts) { throw 'At least one certificate field is required.' }
    $DName = $parts -join ', '
}

if ($wizard) {
    while ($true) {
        $repo = Read-Value 'GitHub repository (owner/repo)' -Optional -Help @(
            'The repository whose GitHub Actions build the app. Example: myuser/myapp',
            "The secrets $($names.Values -join ', ') will be created there",
            'with the GitHub CLI (gh). Press Enter to skip: they will be in the TXT file to paste manually.'
        )
        if (-not $repo) { break }
        if ($repo -match '^[\w.-]+/[\w.-]+$') { $GitHubRepo = $repo; break }
        Write-Warning "Invalid format, expected 'owner/repo'."
    }

    $CopyToClipboard = Read-YesNo 'Also copy the Base64 string to the clipboard?' -Default $false -Help @(
        "Handy to paste it straight into the secret $($names.Keystore)."
    )
}

# --- 1. keytool ---------------------------------------------------------------
$tempJre = $null
$keytool = Find-Keytool
if (-not $keytool) {
    $canDownload = (Test-IsWindows) -and [Environment]::Is64BitOperatingSystem
    $why = if ($Generate) { 'keytool is required to create the keystore.' }
           else { 'keytool is only used to check the password and read the fingerprints.' }
    if ($canDownload -and (Read-YesNo 'Download a portable JRE (deleted at the end)?' -Help @(
            'keytool (part of Java) was not found.', $why))) {
        $tempJre = Join-Path ([IO.Path]::GetTempPath()) ('keystore-jre-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tempJre | Out-Null
        $keytool = Get-PortableKeytool $tempJre
    } elseif ($Generate) {
        throw 'keytool not found. Install a JDK (or Android Studio) and set JAVA_HOME, or add keytool to PATH.'
    } else {
        Write-Warning 'Continuing without keytool: password and alias will NOT be verified.'
    }
}
if ($keytool) { Write-Host "keytool: $keytool" -ForegroundColor Cyan }

# --- 2. Passwords, generation, verification -----------------------------------
$generatedPassword = $false
if ($GeneratePassword -and -not $Generate) {
    Write-Warning '-GeneratePassword is ignored: the keystore already exists, type its password.'
    $GeneratePassword = $false
}
$envStore = 'NKB64_STORE_PASS'
$envKey   = 'NKB64_KEY_PASS'
$fingerprints = @()

try {
    if ($Generate) {
        if (-not $GeneratePassword -and $wizard) {
            $GeneratePassword = Read-YesNo 'Generate a random password?' -Help @(
                "A $PasswordLength-character password with digits, uppercase and lowercase letters and - _ . + : @ /",
                '(safe in CMD, PowerShell, Bash and MySQL). Answer n to type your own.'
            )
        }
        if ($GeneratePassword) {
            $storePassword = New-RandomPassword $PasswordLength
            $generatedPassword = $true
            Write-Host "`nRandom $PasswordLength-character password generated (shown at the end)." -ForegroundColor Cyan
        } else {
            $storePassword = Read-Password 'Keystore password' -Confirm -Help @(
                'Password of the new keystore and its key (at least 8 characters, long and random is best).',
                'Save it in a password manager: without it you can no longer sign updates of the app.',
                "Goes into the secrets $($names.StorePassword) and $($names.KeyPassword) (same value in PKCS12)."
            )
        }
        $keyPassword = $storePassword
    } else {
        $storePassword = Read-Password 'Keystore password' -Help @(
            'Password of the existing keystore file.',
            "Goes into the secret $($names.StorePassword)."
        )
        Write-Help @(
            "Password of the key '$Alias'. Press Enter if it is the same as the keystore password",
            '(always the case for .p12 / PKCS12 keystores).',
            "Goes into the secret $($names.KeyPassword)."
        )
        $keyPassword = ConvertTo-PlainText (Read-Host 'Key password' -AsSecureString)
        if (-not $keyPassword) { $keyPassword = $storePassword }
    }

    # Passwords are handed to keytool through environment variables, so they never
    # appear on the command line and special characters are not an issue.
    Set-Item "Env:$envStore" $storePassword
    Set-Item "Env:$envKey"   $keyPassword

    if ($Generate) {
        $dir = Split-Path -Parent $KeystorePath
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

        Write-Host "`nGenerating RSA $KeySize keystore..." -ForegroundColor Cyan
        & $keytool -genkeypair -v `
            -keystore $KeystorePath -storetype PKCS12 `
            -alias $Alias -keyalg RSA -keysize $KeySize -sigalg SHA256withRSA `
            -validity $ValidityDays -dname $DName `
            -storepass:env $envStore -keypass:env $envKey
        if ($LASTEXITCODE -ne 0) { throw "keytool -genkeypair failed with exit code $LASTEXITCODE." }
    }

    if ($keytool) {
        # Checks keystore password and alias, and reads the certificate fingerprints.
        $listing = & $keytool -list -v -keystore $KeystorePath -alias $Alias -storepass:env $envStore
        if ($LASTEXITCODE -ne 0) {
            throw "Cannot open '$KeystorePath' with alias '$Alias': wrong password or alias.`n$($listing -join "`n")"
        }
        $fingerprints = @($listing | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^(SHA1|SHA256):' })
    }
}
finally {
    Remove-Item "Env:$envStore" -ErrorAction SilentlyContinue
    Remove-Item "Env:$envKey"   -ErrorAction SilentlyContinue
    if ($tempJre -and (Test-Path $tempJre)) { Remove-Item $tempJre -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- 3. Base64 and TXT file ---------------------------------------------------
$bytes  = [System.IO.File]::ReadAllBytes($KeystorePath)
$base64 = [System.Convert]::ToBase64String($bytes)
if ([System.Convert]::FromBase64String($base64).Length -ne $bytes.Length) {
    throw 'Base64 round-trip verification failed.'
}

if (-not $OutputFile) { $OutputFile = [IO.Path]::ChangeExtension($KeystorePath, '.github-secrets.txt') }
$OutputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)

$secrets = [ordered]@{
    ($names.Keystore)      = $base64
    ($names.StorePassword) = $storePassword
    ($names.Alias)         = $Alias
    ($names.KeyPassword)   = $keyPassword
}

$where = if ($GitHubRepo) { "https://github.com/$GitHubRepo/settings/secrets/actions/new" }
         else { 'https://github.com/<owner>/<repo>/settings/secrets/actions/new' }
$line  = '=' * 70
$text  = New-Object System.Collections.Generic.List[string]
$text.Add('GitHub Actions secrets for Android signing')
$text.Add("Created:  $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
$text.Add("Keystore: $KeystorePath")
if ($GitHubRepo) { $text.Add("Repo:     $GitHubRepo") }
$text.Add('')
$text.Add('!!! This file contains your passwords in plain text.')
$text.Add('!!! Delete it as soon as the secrets are saved in GitHub. Never commit it.')
$text.Add('')
$text.Add('Where: Settings > Secrets and variables > Actions > New repository secret')
$text.Add("       $where")
$text.Add('For each block: copy the line under "Name" into the Name field,')
$text.Add('and the line under "Secret" into the Secret field.')
foreach ($entry in $secrets.GetEnumerator()) {
    $text.Add('')
    $text.Add($line)
    $text.Add('Name:')
    $text.Add($entry.Key)
    $text.Add('')
    $text.Add('Secret:')
    $text.Add($entry.Value)
}
$text.Add('')
$text.Add($line)
$text.Add('Not secrets, for reference (Google Play Console, Firebase, F-Droid...):')
$text.Add("  Alias:   $Alias")
foreach ($f in $fingerprints) { $text.Add("  $f") }
if ($Generate) {
    if ($generatedPassword) { $text.Add("  Password: generated automatically ($PasswordLength characters)") }
    $text.Add("  Owner:   $DName")
    $text.Add("  Key:     RSA $KeySize, SHA256withRSA, valid $ValidityDays days")
}

[System.IO.File]::WriteAllText($OutputFile, ($text -join [Environment]::NewLine) + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host "Keystore : $KeystorePath ($($bytes.Length) bytes)" -ForegroundColor Green
Write-Host "Secrets  : $OutputFile" -ForegroundColor Green
foreach ($f in $fingerprints) { Write-Host "  $f" }

if ($generatedPassword) {
    Write-Host ''
    Write-Host 'Generated password (keystore and key) - save it NOW in a password manager:' -ForegroundColor Yellow
    Write-Host "  $storePassword" -ForegroundColor Yellow
}

if ($CopyToClipboard) {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
        Set-Clipboard -Value $base64
        Write-Host "Base64 ($($names.Keystore)) copied to the clipboard." -ForegroundColor Green
    } else {
        Write-Warning 'Set-Clipboard is not available here; copy the value from the TXT file.'
    }
}

# --- 4. Upload with GitHub CLI ------------------------------------------------
if ($GitHubRepo) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        Write-Warning 'GitHub CLI (gh) not found: add the secrets manually from the TXT file (install gh from https://cli.github.com).'
    } else {
        Write-Host "`nUploading secrets to $GitHubRepo..." -ForegroundColor Cyan
        $failed = 0
        foreach ($entry in $secrets.GetEnumerator()) {
            # Values go through stdin so they never appear on the command line.
            $entry.Value | gh secret set $entry.Key --repo $GitHubRepo
            if ($LASTEXITCODE -ne 0) { $failed++; Write-Warning "Failed to set $($entry.Key)." }
            else { Write-Host "  $($entry.Key) set." -ForegroundColor Green }
        }
        if ($failed) { Write-Warning "Some secrets were not set: check 'gh auth status' and use the TXT file." }
    }
}

$storePassword = $null; $keyPassword = $null
Write-Host ''
Write-Warning "Back up '$KeystorePath' and its password in at least two safe places: without them you cannot update the app."
Write-Warning "Delete '$OutputFile' once the secrets are saved: it contains the passwords in plain text."
