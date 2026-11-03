# Detection validation on real attack telemetry

5 OTRF Security-Datasets, 3,504 real Windows events.

**Active rules: 6/6 expected detections, 0 false-positive alerts, 0 missed.**

| Rule | T1547.001 | T1069.001 | T1003.002 | T1003.001 | T1053.005 |
|---|---|---|---|---|---|
| threat_intel_match | · | · | · | · | · |
| phish_delivered | · | · | · | · | · |
| large_outbound_transfer | · | · | · | · | · |
| proxy_risky_category | · | · | · | · | · |
| lsass_process_access | · | · | · | ✅ 1 | · |
| lsass_dump_comsvcs | · | · | · | ✅ 1 | · |
| net_localgroup_admins | · | ✅ 2 | · | · | · |
| powershell_encoded_command | · | · | · | · | · |
| reg_save_sensitive_hive | · | · | ✅ 1 | · | · |
| schtasks_create_from_shell | · | · | · | · | ✅ 1 |
| run_key_persistence | ✅ 1 | · | · | · | · |
| privileged_group_member_added | · | · | · | · | · |
| run_key_naive *(deprecated)* | ✅ 1 | ❌ 2 FP | ❌ 2 FP | · | · |

Columns: T1547.001 = T1547.001 Run key persistence (657 events); T1069.001 = T1069.001 Local group discovery (884 events); T1003.002 = T1003.002 SAM hive export (738 events); T1003.001 = T1003.001 LSASS memory dump (184 events); T1053.005 = T1053.005 Scheduled task (1041 events)