# Reachability Analysis Report

**APK:** com.example.app.apk
**Date:** 2026-03-21 14:32:01
**Findings Source:** Mobsf
**Total Findings:** 8 | Reachable: 3 | Not Reachable: 4 | Unresolved: 1
**Reachable with FP Risk Flags:** 2

---

## [REACHABLE] SSL Certificate Verification Disabled — Critical

**Sink:** `Lcom/example/net/HttpClient;->checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V`
**Entry Point:** `Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V`
**Match Confidence:** Exact class + method
**Call Chain:** `MainActivity.onCreate` → `NetworkManager.init` → `HttpClient.checkServerTrusted`
**Evidence:** Path length: 3 hops

---

## [REACHABLE] Insecure WebView — High

**Sink:** `Lcom/example/WebHelper;->loadUrl(Ljava/lang/String;)V`
**Entry Point:** `Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V`
**Match Confidence:** Exact class + method
**Call Chain:** `MainActivity.onCreate` → `HelperClass.init` → `WebHelper.loadUrl`
**Evidence:** Path length: 3 hops
⚠️ **FP Risk:** Call chain passes through reflection at hop 2

---

## [REACHABLE] Insecure Random Number Generator — High

**Sink:** `Lcom/example/CryptoHelper;->generateToken()Ljava/lang/String;`
**Entry Point:** `Lcom/example/LoginActivity;->onResume()V`
**Match Confidence:** Exact class only
**Call Chain:** `LoginActivity.onResume` → `AuthManager.refreshToken` → `CryptoHelper.generateToken`
**Evidence:** Path length: 3 hops
⚠️ **FP Risk:** Sink resides in a third-party library `com.example.crypto` — confirm whether this vulnerability applies to this version

---

## [NOT REACHABLE] Hardcoded Credentials — Medium

**Sink:** `Lcom/example/AuthUtil;->getSecret()Ljava/lang/String;`
**Entry Point(s) Checked:** 4
**Reason:** No path found within 15 hops from any entry point
**Match Confidence:** Exact class + method

---

## [NOT REACHABLE] Clipboard Data Access — Warning

**Sink:** `Lcom/example/utils/ClipHelper;->getClipData()Ljava/lang/String;`
**Entry Point(s) Checked:** 4
**Reason:** No path found within 15 hops from any entry point
**Match Confidence:** Exact class + method

---

## [NOT REACHABLE] Logging of Sensitive Data — Low

**Sink:** `Lcom/example/Logger;->logUserData(Ljava/lang/String;)V`
**Entry Point(s) Checked:** 4
**Reason:** No path found within 15 hops from any entry point
**Match Confidence:** Exact method only

---

## [NOT REACHABLE] Weak Hashing Algorithm — Medium

**Sink:** `Lcom/example/HashUtil;->md5(Ljava/lang/String;)Ljava/lang/String;`
**Entry Point(s) Checked:** 4
**Reason:** No path found within 15 hops from any entry point
**Match Confidence:** Exact class + method

---

## [UNRESOLVED] SQL Injection — High

**Raw Finding:** `com.example.db.QueryBuilder.rawQuery`
**Reason:** Sink method could not be matched to any call graph node
**Match Confidence:** No match

---
