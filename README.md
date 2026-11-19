# CreateKeyBase64

A PowerShell script that creates (or reuses) an Android signing keystore and prepares
everything GitHub Actions needs to sign release builds:

- a **TXT file with all the secrets** (name and value) ready to copy and paste into GitHub;
- optionally, the secrets **uploaded directly** with the GitHub CLI.

## Quick start (Windows)

Double-click **`New-KeystoreBase64.cmd`**. The script asks for every value and explains
next to each question what to enter and which secret it goes into.

The `.cmd` launcher runs the script with the Execution Policy bypassed for that run only,
prefers PowerShell 7 when installed, and pauses at the end when started by double-click.
It accepts the same parameters as the script (`New-KeystoreBase64.cmd /?` shows them).

From PowerShell:

```powershell
./New-KeystoreBase64.ps1          # guided mode
./New-KeystoreBase64.ps1 -Help    # parameter summary
```

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ (Windows, macOS, Linux)
- `keytool`, searched in `JAVA_HOME`, `PATH`, Android Studio's bundled JDK and the common
  JDK folders. If it is missing on Windows x64, the script offers to download a portable
  Temurin 17 JRE, use it and delete it at the end.
- [GitHub CLI](https://cli.github.com) (`gh auth login`), only to upload the secrets with `-GitHubRepo`

## Parameters

All parameters are optional: any required value that is missing is asked for.

| Parameter          | Description                                                            | Default                         |
| ------------------ | ---------------------------------------------------------------------- | ------------------------------- |
| `-KeystorePath`    | Keystore to encode, or to create (`.p12`, `.jks`, `.keystore`)        | asked                           |
| `-Generate`        | Create a new keystore (offered anyway if the file does not exist)     |                                 |
| `-Alias`           | Key alias, goes into `KEY_ALIAS`                                       | asked                           |
| `-DName`           | Certificate owner, e.g. `"CN=John Doe, O=Example, L=Rome, C=IT"`       | asked field by field            |
| `-KeySize`         | RSA key size: `2048`, `3072`, `4096`                                   | `4096`                          |
| `-ValidityDays`    | Certificate validity in days                                           | `10000` (about 27 years)        |
| `-SecretPrefix`    | Prefix for secret names: `MYAPP` gives `MYAPP_KEYSTORE_BASE64`, ...    | none                            |
| `-OutputFile`      | TXT file with all the secrets                                          | `<keystore>.github-secrets.txt` |
| `-GitHubRepo`      | `owner/repo`: upload the secrets with `gh secret set`                  |                                 |
| `-CopyToClipboard` | Also copy the Base64 string to the clipboard                           |                                 |
| `-Help`, `-h`      | Show the parameter summary                                             |                                 |

Passwords are always asked for with hidden input, never passed as parameters.

### Examples

```powershell
# New keystore, everything else asked
./New-KeystoreBase64.ps1 -KeystorePath .\myapp.p12 -Generate -Alias myapp -DName "CN=John Doe, C=IT"

# Existing keystore, prefixed secret names, uploaded with gh
./New-KeystoreBase64.ps1 -KeystorePath .\old.jks -Alias upload -SecretPrefix MYAPP -GitHubRepo myuser/myapp
```

## What the script does

1. **New keystore:** PKCS12, RSA 4096, `SHA256withRSA`, one password for both the keystore
   and the key (PKCS12 requires them to be equal). An existing file is never overwritten.
2. **Existing keystore:** opens it with keytool to check the password and alias before
   writing anything.
3. Passwords reach keytool through environment variables (`-storepass:env`), so they never
   appear on the command line. The variables are removed at the end.
4. Encodes the keystore as single-line Base64 (no line breaks, unlike `certutil -encode`).
5. Writes the TXT file, which looks like this:

```
GitHub Actions secrets for Android signing
...
Where: Settings > Secrets and variables > Actions > New repository secret
       https://github.com/myuser/myapp/settings/secrets/actions/new

======================================================================
Name:
KEYSTORE_BASE64

Secret:
MIIKXAIBAzCCCgYGCSqGSIb3DQEHAaCCCfcEggnzMIIJ7zCCBWMGCSqGSIb3DQEHAaCC...

======================================================================
Name:
KEYSTORE_PASSWORD
...
======================================================================
Not secrets, for reference (Google Play Console, Firebase, F-Droid...):
  Alias:   myapp
  SHA1: 4E:20:EF:...
  SHA256: 37:48:88:...
```

## Secrets

| Secret              | Value                                       |
| ------------------- | ------------------------------------------- |
| `KEYSTORE_BASE64`   | The keystore encoded as Base64              |
| `KEYSTORE_PASSWORD` | Keystore password                           |
| `KEY_ALIAS`         | Key alias                                   |
| `KEY_PASSWORD`      | Key password (same as keystore for PKCS12) |

With `-SecretPrefix MYAPP` they become `MYAPP_KEYSTORE_BASE64`, `MYAPP_KEYSTORE_PASSWORD`, ...

## Using the secrets in a workflow

```yaml
- name: Decode keystore
  run: echo "${{ secrets.KEYSTORE_BASE64 }}" | base64 --decode > "$RUNNER_TEMP/release.p12"

- name: Build signed release
  run: ./gradlew assembleRelease bundleRelease
  env:
    KEYSTORE_PATH: ${{ runner.temp }}/release.p12
    KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
    KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
    KEY_PASSWORD: ${{ secrets.KEY_PASSWORD }}
```

And in `app/build.gradle.kts`:

```kotlin
android {
    signingConfigs {
        create("release") {
            System.getenv("KEYSTORE_PATH")?.let { storeFile = file(it) }
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = System.getenv("KEY_ALIAS")
            keyPassword = System.getenv("KEY_PASSWORD")
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

## Security

- The TXT file contains the passwords in plain text: **delete it** once the secrets are saved.
- Never commit the keystore or the TXT file (both are in `.gitignore`).
- Back up the keystore and its password in at least two safe places (e.g. a password
  manager and an offline backup): without them you cannot publish updates of the app.
- The certificate owner (DN) is readable by anyone who opens the APK.
