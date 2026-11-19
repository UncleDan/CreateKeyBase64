# CreateKeyBase64

A PowerShell script that creates (or reuses) an Android signing keystore and encodes it
as Base64, so you can store it in a GitHub Actions secret and sign release builds in CI.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ (Windows, macOS, Linux)
- A JDK providing `keytool` (only needed with `-Generate`). The script looks in
  `JAVA_HOME`, then `PATH`, then Android Studio's bundled JDK.
- [GitHub CLI](https://cli.github.com) (only needed with `-GitHubRepo`)

## Usage

Generate a new keystore, encode it, and copy the Base64 string to the clipboard:

```powershell
./New-KeystoreBase64.ps1 -KeystorePath .\release.jks -Generate -Alias upload -CopyToClipboard
```

Encode an existing keystore:

```powershell
./New-KeystoreBase64.ps1 -KeystorePath .\existing.keystore -Alias mykey
```

Encode and upload all four secrets directly to a repository:

```powershell
./New-KeystoreBase64.ps1 -KeystorePath .\release.jks -Alias upload -GitHubRepo myuser/myapp
```

If script execution is blocked on Windows, run it for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Parameters

| Parameter          | Description                                                              |
| ------------------ | ------------------------------------------------------------------------ |
| `-KeystorePath`    | Keystore to encode, or to create with `-Generate` (required)             |
| `-Generate`        | Create a new keystore with `keytool`                                     |
| `-Alias`           | Key alias                                                                |
| `-OutputFile`      | Where to write the Base64 string (default `<keystore>.base64.txt`)       |
| `-ValidityDays`    | Key validity when generating (default `10000`)                           |
| `-DName`           | Certificate subject, e.g. `"CN=John Doe, O=Example, C=US"` (else prompted) |
| `-CopyToClipboard` | Copy the Base64 string to the clipboard                                  |
| `-GitHubRepo`      | `owner/repo`: upload the secrets with `gh secret set`                    |
| `-SecretPrefix`    | Prefix for secret names (default `ANDROID`)                              |

Passwords are always prompted for securely and are never passed as script arguments.

## GitHub secrets

| Secret                      | Value                                   |
| --------------------------- | --------------------------------------- |
| `ANDROID_KEYSTORE_BASE64`   | Contents of the generated `.base64.txt` |
| `ANDROID_KEYSTORE_PASSWORD` | Keystore password                       |
| `ANDROID_KEY_ALIAS`         | Key alias                               |
| `ANDROID_KEY_PASSWORD`      | Key password                            |

Add them under **Settings > Secrets and variables > Actions**, or let the script do it with `-GitHubRepo`.

## Using the secrets in a workflow

```yaml
- name: Decode keystore
  run: echo "${{ secrets.ANDROID_KEYSTORE_BASE64 }}" | base64 --decode > "$RUNNER_TEMP/release.jks"

- name: Build signed release
  run: ./gradlew assembleRelease bundleRelease
  env:
    ANDROID_KEYSTORE_PATH: ${{ runner.temp }}/release.jks
    ANDROID_KEYSTORE_PASSWORD: ${{ secrets.ANDROID_KEYSTORE_PASSWORD }}
    ANDROID_KEY_ALIAS: ${{ secrets.ANDROID_KEY_ALIAS }}
    ANDROID_KEY_PASSWORD: ${{ secrets.ANDROID_KEY_PASSWORD }}
```

And in `app/build.gradle.kts`:

```kotlin
android {
    signingConfigs {
        create("release") {
            System.getenv("ANDROID_KEYSTORE_PATH")?.let { storeFile = file(it) }
            storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
            keyAlias = System.getenv("ANDROID_KEY_ALIAS")
            keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
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

- Never commit the keystore or the `.base64.txt` file (both are in `.gitignore`).
- Back up the keystore and its passwords: if you lose them you cannot publish updates
  (unless you use Play App Signing with an upload key that can be reset).
- Delete the `.base64.txt` file once the secret has been saved.
