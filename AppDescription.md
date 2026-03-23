# ReachabilityTestApp

**WARNING: This app is intentionally vulnerable and is for authorized security research and testing only. Do NOT publish or deploy this application.**

## Purpose

This Android application serves as a deliberately vulnerable target for reachability analysis testing, including:
- Network reachability analysis
- Code/call graph reachability analysis
- Android component reachability analysis

## Intentional Vulnerabilities

### 1. Hardcoded Credentials (`MainActivity.java`)
- `API_KEY` and `DB_PASSWORD` are hardcoded as public constants
- Referenced in `logCredentials()` and displayed in `ExposedActivity`
- **Reachability test**: Trace data flow from constants → log output → UI display

### 2. Cleartext HTTP Traffic (`NetworkActivity.java`)
- Plain HTTP request to `http://example.com` via `fetchHttp()`
- Network security config allows cleartext for all domains (`network_security_config.xml`)
- **Reachability test**: Identify all HTTP (non-HTTPS) network calls

### 3. Disabled SSL Validation (`NetworkActivity.java`)
- `fetchHttpsNoPinning()` uses a custom TrustManager that accepts all certificates
- Hostname verification is disabled
- **Reachability test**: Trace TrustManager implementations that skip validation

### 4. Hidden Analytics Endpoint (`NetworkActivity.java`)
- `sendToAnalytics()` calls `http://analytics.internal.corp/track`
- Only reachable from exception handlers in `fetchHttp()` and `fetchHttpsNoPinning()`
- **Reachability test**: Discover network calls hidden in non-obvious code paths (exception handlers)

### 5. Insecure Storage (`StorageActivity.java`)
- SharedPreferences opened with `MODE_WORLD_READABLE` (mode 1)
- Secret token written to external storage as plaintext (`secrets.txt`)
- `logSensitiveData()` logs the secret via `Log.d()` with tag "SECRETS"
- **Reachability test**: Trace sensitive data flow to insecure storage and log sinks

### 6. SQL Injection (`SqlActivity.java`)
- `performLogin()` builds SQL query via direct string concatenation with user input
- No parameterized queries or input sanitization
- **Reachability test**: Trace user input from EditText → raw SQL query execution

### 7. Destructive Hidden Query (`SqlActivity.java`)
- `executeAdminQuery()` runs `DROP TABLE IF EXISTS users`
- Only reachable via long-press on the Login button (non-obvious reachability path)
- **Reachability test**: Discover destructive DB operations through UI event analysis

### 8. Exported Activity Without Permission (`ExposedActivity.java`)
- Declared `exported="true"` with a custom intent filter
- Displays hardcoded API key and DB password to any caller
- No permission checks
- **Reachability test**: Identify exported components accessible by external apps

### 9. Exported Service Without Permission (`PhantomService.java`)
- Empty service declared `exported="true"` with no permissions
- **Reachability test**: Identify exported components with no permission protection

## ADB Commands

Trigger ExposedActivity from another app or ADB:

```bash
# By component name
adb shell am start -n com.test.reachability/.ExposedActivity

# By intent action
adb shell am start -a com.test.reachability.ADMIN

# Start the phantom service
adb shell am startservice -n com.test.reachability/.PhantomService
```

## Build

```bash
./gradlew assembleDebug
```

The debug APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

## Dead Code Test Cases

The following intentionally unreachable/dead vulnerable code patterns have been injected.
A correctly functioning reachability analysis tool should **NOT** flag any of these as reachable issues.

| Pattern | File | Simulated Vuln | Expected Tool Result |
|---|---|---|---|
| Dead method: `leakCredentialsToUrl()` | MainActivity.java | Credential exfil via HTTP | NOT reachable |
| Dead method: `nukeDatabase()` | MainActivity.java | Destructive DB operation | NOT reachable |
| Dead method: `writeCredsToExternalStorage()` | MainActivity.java | Insecure file write | NOT reachable |
| `if(false)` branch | NetworkActivity.java | Credential in URL param | NOT reachable |
| `if(shouldDelete==false)` branch | StorageActivity.java | Secret log + file wipe | NOT reachable |
| `if(debugMode==1)` branch | SqlActivity.java | Schema dump via raw SQL | NOT reachable |
| Orphaned class: `DeadAdminClient` | DeadAdminClient.java | HTTP auth + contact exfil | NOT reachable |
| Orphaned class: `LegacyDataUploader` | LegacyDataUploader.java | Secrets upload via HTTP | NOT reachable |
| Code after return | SqlActivity.java | Destructive SQL | NOT reachable |
| Code after throw | NetworkActivity.java | Cred exfil in analytics | NOT reachable |
