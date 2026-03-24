# Reachability Analysis Report

**APK:** reachability-apk-v2.apk  
**Date:** 2026-03-23 23:00:47  
**Findings Source:** Mobsf  
**Total Findings:** 28 | Reachable: 20 | Not Reachable: 8 | Unresolved: 0  
**Reachable with FP Risk Flags:** 12  

---

## [REACHABLE] App can read/write to External Storage. Any App can read data written to External Storage. - Warning

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] App can read/write to External Storage. Any App can read data written to External Storage. - Warning

**Sink:** `Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Entry Point:** `Lcom/test/reachability/StorageActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `StorageActivity.onCreate -> Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database. - Warning

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database. - Warning

**Sink:** `Lcom/test/reachability/SqlActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/SqlActivity;)V`  
**Entry Point:** `Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `SqlActivity.onCreate -> Lcom/test/reachability/SqlActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/SqlActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database. - Warning

**Sink:** `Lcom/test/reachability/UserDatabaseHelper;-><init>(Landroid/content/Context;)V`  
**Entry Point:** `Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `SqlActivity.onCreate -> Lcom/test/reachability/UserDatabaseHelper;-><init>(Landroid/content/Context;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] Files may contain hardcoded sensitive information like usernames, passwords, keys etc. - Warning

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] Files may contain hardcoded sensitive information like usernames, passwords, keys etc. - Warning

**Sink:** `Lcom/test/reachability/SqlActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/SqlActivity;)V`  
**Entry Point:** `Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `SqlActivity.onCreate -> Lcom/test/reachability/SqlActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/SqlActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] Files may contain hardcoded sensitive information like usernames, passwords, keys etc. - Warning

**Sink:** `Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Entry Point:** `Lcom/test/reachability/StorageActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `StorageActivity.onCreate -> Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] The App logs information. Sensitive information should never be logged. - Info

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] The App logs information. Sensitive information should never be logged. - Info

**Sink:** `Lcom/test/reachability/SqlActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/SqlActivity;)V`  
**Entry Point:** `Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `SqlActivity.onCreate -> Lcom/test/reachability/SqlActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/SqlActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] The App logs information. Sensitive information should never be logged. - Info

**Sink:** `Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Entry Point:** `Lcom/test/reachability/StorageActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `StorageActivity.onCreate -> Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] This App uses SSL certificate pinning to detect or  prevent MITM attacks in secure communication channel. - Info

**Sink:** `Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Entry Point:** `Lcom/test/reachability/NetworkActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `NetworkActivity.onCreate -> Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] Starting Activity - Info

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] Local File I/O Operations - Info

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] Local File I/O Operations - Info

**Sink:** `Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Entry Point:** `Lcom/test/reachability/NetworkActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `NetworkActivity.onCreate -> Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] Local File I/O Operations - Info

**Sink:** `Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Entry Point:** `Lcom/test/reachability/StorageActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `StorageActivity.onCreate -> Lcom/test/reachability/StorageActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/StorageActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] Inter Process Communication - Info

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] HTTP Connection - Info

**Sink:** `Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Entry Point:** `Lcom/test/reachability/MainActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `MainActivity.onCreate -> Lcom/test/reachability/MainActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/MainActivity;)V`  
**Evidence:** Path length: 2 hops  

---

## [REACHABLE] HTTP Connection - Info

**Sink:** `Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Entry Point:** `Lcom/test/reachability/NetworkActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `NetworkActivity.onCreate -> Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [REACHABLE] HTTPS Connection - Info

**Sink:** `Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Entry Point:** `Lcom/test/reachability/NetworkActivity;->onCreate(Landroid/os/Bundle;)V`  
**Match Confidence:** Exact class only  
**Call Chain:** `NetworkActivity.onCreate -> Lcom/test/reachability/NetworkActivity$$ExternalSyntheticLambda0;-><init>(Lcom/test/reachability/NetworkActivity;)V`  
**Evidence:** Path length: 2 hops  
  **FP Risk:** Entry point is not exported - only reachable from within the same application  
  **FP Risk:** Entry point has no intent filter and is unexported - unlikely to be triggered externally  

---

## [NOT REACHABLE] App can read/write to External Storage. Any App can read data written to External Storage. - Warning

**Sink:** `Lcom/test/reachability/LegacyDataUploader;-><init>()V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] The App logs information. Sensitive information should never be logged. - Info

**Sink:** `Lcom/test/reachability/DeadAdminClient;-><init>(Landroid/content/Context;)V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] The App logs information. Sensitive information should never be logged. - Info

**Sink:** `Lcom/test/reachability/LegacyDataUploader;-><init>()V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] Local File I/O Operations - Info

**Sink:** `Lcom/test/reachability/DeadAdminClient;-><init>(Landroid/content/Context;)V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] Local File I/O Operations - Info

**Sink:** `Lcom/test/reachability/LegacyDataUploader;-><init>()V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] Inter Process Communication - Info

**Sink:** `Lcom/test/reachability/PhantomService;-><init>()V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] HTTP Connection - Info

**Sink:** `Lcom/test/reachability/DeadAdminClient;-><init>(Landroid/content/Context;)V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---

## [NOT REACHABLE] HTTP Connection - Info

**Sink:** `Lcom/test/reachability/LegacyDataUploader;-><init>()V`  
**Entry Point(s) Checked:** 11  
**Reason:** No path found from any entry point (depth limit: 15)  
**Match Confidence:** Exact class only  

---
