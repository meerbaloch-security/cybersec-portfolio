# Vulnerability priority report: `package-lock.json`

Scanned **8** packages and found **48** known vulnerabilities.

> **21** are rated High or Critical by CVSS alone. After adding real-world exploitation data, **3** need fixing now, cutting urgent work by **86%**.

| Tier | Meaning | Count |
|---|---|---|
| **P1** | Fix now (days): exploited in the wild, or likely to be exploited and severe | 3 |
| **P2** | Fix soon (weeks): likely to be exploited, or critical severity | 1 |
| **P3** | Plan (next release): high severity or some exploitation likelihood | 25 |
| **P4** | Backlog: low likelihood and lower severity | 19 |

## Upgrade plan

| Package | Current | Upgrade to | Vulns fixed | Worst tier |
|---|---|---|---|---|
| axios | 0.21.0 | **0.33.0** | 25 | P1 |
| lodash | 4.17.15 | **4.18.0** | 6 | P1 |
| qs | 6.7.0 | **6.16.1** | 5 | P1 |
| minimist | 1.2.0 | **1.2.6** | 2 | P2 |
| jsonwebtoken | 8.5.1 | **9.0.0** | 3 | P3 |
| node-fetch | 2.6.0 | **2.6.7** | 2 | P3 |
| ws | 7.4.5 | **7.5.11** | 3 | P3 |
| express | 4.17.1 | **4.20.0** | 2 | P4 |

## All findings

| Tier | Package | Advisory | CVE | CVSS | EPSS (percentile) | KEV | Fixed in | Why this tier |
|---|---|---|---|---|---|---|---|---|
| P1 | lodash 4.17.15 | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | 7.2 | 21.3% (98%) | No | 4.17.21 | EPSS 21.3% and CVSS 7.2 |
| P1 | qs 6.7.0 | [GHSA-hrpp-h998-j3pp](https://osv.dev/vulnerability/GHSA-hrpp-h998-j3pp) | CVE-2022-24999 | 7.5 | 15.7% (97%) | No | 6.7.3 | EPSS 15.7% and CVSS 7.5 |
| P1 | axios 0.21.0 | [GHSA-pjwm-pj3p-43mv](https://osv.dev/vulnerability/GHSA-pjwm-pj3p-43mv) | CVE-2026-44492 | 8.6 | 12.3% (96%) | No | 0.32.0 | EPSS 12.3% and CVSS 8.6 |
| P2 | minimist 1.2.0 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | 9.8 | 4.6% (92%) | No | 1.2.6 | critical CVSS 9.8 |
| P3 | axios 0.21.0 | [GHSA-cph5-m8f7-6c5x](https://osv.dev/vulnerability/GHSA-cph5-m8f7-6c5x) | CVE-2021-3749 | 7.5 | 8.5% (95%) | No | 0.21.2 | CVSS 7.5, EPSS 8.52% |
| P3 | lodash 4.17.15 | [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) | CVE-2020-28500 | 5.3 | 7.3% (94%) | No | 4.17.21 | CVSS 5.3, EPSS 7.34% |
| P3 | axios 0.21.0 | [GHSA-hfxv-24rg-xrqf](https://osv.dev/vulnerability/GHSA-hfxv-24rg-xrqf) | CVE-2026-44496 | 7.5 | 5.4% (93%) | No | 0.32.0 | CVSS 7.5, EPSS 5.41% |
| P3 | lodash 4.17.15 | [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) | CVE-2020-8203 | 7.4 | 5.2% (93%) | No | 4.17.19 | CVSS 7.4, EPSS 5.21% |
| P3 | ws 7.4.5 | [GHSA-6fc8-4gx4-v693](https://osv.dev/vulnerability/GHSA-6fc8-4gx4-v693) | CVE-2021-32640 | 5.3 | 2.8% (87%) | No | 7.4.6 | CVSS 5.3, EPSS 2.82% |
| P3 | lodash 4.17.15 | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) | CVE-2026-4800 | 8.1 | 2.8% (87%) | No | 4.18.0 | CVSS 8.1, EPSS 2.81% |
| P3 | axios 0.21.0 | [GHSA-43fc-jf86-j433](https://osv.dev/vulnerability/GHSA-43fc-jf86-j433) | CVE-2026-25639 | 7.5 | 2.8% (86%) | No | 0.30.3 | CVSS 7.5, EPSS 2.80% |
| P3 | axios 0.21.0 | [GHSA-4w2v-q235-vp99](https://osv.dev/vulnerability/GHSA-4w2v-q235-vp99) | CVE-2020-28168 | 5.9 | 2.4% (84%) | No | 0.21.1 | CVSS 5.9, EPSS 2.36% |
| P3 | axios 0.21.0 | [GHSA-fvcv-3m26-pcqx](https://osv.dev/vulnerability/GHSA-fvcv-3m26-pcqx) | CVE-2026-40175 | 4.8 | 1.9% (80%) | No | 0.31.0 | CVSS 4.8, EPSS 1.95% |
| P3 | minimist 1.2.0 | [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) | CVE-2020-7598 | 5.6 | 1.9% (80%) | No | 1.2.3 | CVSS 5.6, EPSS 1.93% |
| P3 | lodash 4.17.15 | [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) | CVE-2025-13465 | 6.5 | 1.8% (79%) | No | 4.17.23 | CVSS 6.5, EPSS 1.82% |
| P3 | node-fetch 2.6.0 | [GHSA-w7rc-rwvf-8q5r](https://osv.dev/vulnerability/GHSA-w7rc-rwvf-8q5r) | CVE-2020-15168 | 2.6 | 1.7% (77%) | No | 2.6.1 | CVSS 2.6, EPSS 1.69% |
| P3 | node-fetch 2.6.0 | [GHSA-r683-j2x4-v87g](https://osv.dev/vulnerability/GHSA-r683-j2x4-v87g) | CVE-2022-0235 | 8.8 | 1.7% (77%) | No | 2.6.7 | CVSS 8.8, EPSS 1.65% |
| P3 | ws 7.4.5 | [GHSA-96hv-2xvq-fx4p](https://osv.dev/vulnerability/GHSA-96hv-2xvq-fx4p) | CVE-2026-48779 | 7.5 | 1.4% (73%) | No | 7.5.11 | CVSS 7.5, EPSS 1.43% |
| P3 | ws 7.4.5 | [GHSA-3h5v-q93c-6h6q](https://osv.dev/vulnerability/GHSA-3h5v-q93c-6h6q) | CVE-2024-37890 | 7.5 | 1.4% (72%) | No | 7.5.10 | CVSS 7.5, EPSS 1.36% |
| P3 | axios 0.21.0 | [GHSA-3p68-rc4w-qgx5](https://osv.dev/vulnerability/GHSA-3p68-rc4w-qgx5) | CVE-2025-62718 | 4.8 | 1.2% (68%) | No | 0.31.0 | CVSS 4.8, EPSS 1.19% |
| P3 | axios 0.21.0 | [GHSA-pf86-5x62-jrwf](https://osv.dev/vulnerability/GHSA-pf86-5x62-jrwf) | CVE-2026-42033 | 7.4 | 0.9% (59%) | No | 0.31.1 | CVSS 7.4, EPSS 0.87% |
| P3 | axios 0.21.0 | [GHSA-3g43-6gmg-66jw](https://osv.dev/vulnerability/GHSA-3g43-6gmg-66jw) | CVE-2026-44495 | 7.0 | 0.9% (58%) | No | 0.31.1 | CVSS 7.0, EPSS 0.85% |
| P3 | axios 0.21.0 | [GHSA-jr5f-v2jv-69x6](https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6) | CVE-2025-27152 | 7.5 | 0.8% (56%) | No | 0.30.0 | CVSS 7.5, EPSS 0.79% |
| P3 | axios 0.21.0 | [GHSA-62hf-57xw-28j9](https://osv.dev/vulnerability/GHSA-62hf-57xw-28j9) | CVE-2026-42039 | 7.5 | 0.8% (56%) | No | 0.31.1 | CVSS 7.5, EPSS 0.77% |
| P3 | axios 0.21.0 | [GHSA-pmwg-cvhr-8vh7](https://osv.dev/vulnerability/GHSA-pmwg-cvhr-8vh7) | CVE-2026-42043 | 7.2 | 0.7% (54%) | No | 0.31.1 | CVSS 7.2, EPSS 0.71% |
| P3 | axios 0.21.0 | [GHSA-p92q-9vqr-4j8v](https://osv.dev/vulnerability/GHSA-p92q-9vqr-4j8v) | CVE-2026-44487 | 7.5 | 0.7% (53%) | No | 0.32.0 | CVSS 7.5, EPSS 0.69% |
| P3 | axios 0.21.0 | [GHSA-j5f8-grm9-p9fc](https://osv.dev/vulnerability/GHSA-j5f8-grm9-p9fc) | CVE-2026-44486 | 7.5 | 0.6% (46%) | No | 0.32.0 | CVSS 7.5, EPSS 0.55% |
| P3 | jsonwebtoken 8.5.1 | [GHSA-8cf7-32gw-wr33](https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33) | CVE-2022-23539 | 8.1 | 0.5% (44%) | No | 9.0.0 | CVSS 8.1, EPSS 0.52% |
| P3 | axios 0.21.0 | [GHSA-6chq-wfr3-2hj9](https://osv.dev/vulnerability/GHSA-6chq-wfr3-2hj9) | CVE-2026-42035 | 7.4 | 0.4% (35%) | No | 0.31.1 | CVSS 7.4, EPSS 0.40% |
| P4 | jsonwebtoken 8.5.1 | [GHSA-hjrf-2m68-5959](https://osv.dev/vulnerability/GHSA-hjrf-2m68-5959) | CVE-2022-23541 | 5.0 | 0.8% (57%) | No | 9.0.0 | CVSS 5.0, EPSS 0.81% |
| P4 | express 4.17.1 | [GHSA-rv95-896h-c2vc](https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc) | CVE-2024-29041 | 6.1 | 0.8% (56%) | No | 4.19.2 | CVSS 6.1, EPSS 0.79% |
| P4 | axios 0.21.0 | [GHSA-wf5p-g6vw-rhxx](https://osv.dev/vulnerability/GHSA-wf5p-g6vw-rhxx) | CVE-2023-45857 | 6.5 | 0.7% (54%) | No | 0.28.0 | CVSS 6.5, EPSS 0.73% |
| P4 | axios 0.21.0 | [GHSA-w9j2-pvgh-6h63](https://osv.dev/vulnerability/GHSA-w9j2-pvgh-6h63) | CVE-2026-42041 | 4.8 | 0.7% (51%) | No | 0.31.1 | CVSS 4.8, EPSS 0.66% |
| P4 | jsonwebtoken 8.5.1 | [GHSA-qwph-4952-7xr6](https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6) | CVE-2022-23540 | 6.4 | 0.6% (47%) | No | 9.0.0 | CVSS 6.4, EPSS 0.57% |
| P4 | qs 6.7.0 | [GHSA-w7fw-mjwx-w883](https://osv.dev/vulnerability/GHSA-w7fw-mjwx-w883) | CVE-2026-2391 | 3.7 | 0.5% (46%) | No | 6.14.2 | CVSS 3.7, EPSS 0.54% |
| P4 | express 4.17.1 | [GHSA-qw6h-vgh9-j6wx](https://osv.dev/vulnerability/GHSA-qw6h-vgh9-j6wx) | CVE-2024-43796 | 5.0 | 0.5% (42%) | No | 4.20.0 | CVSS 5.0, EPSS 0.49% |
| P4 | qs 6.7.0 | [GHSA-6rw7-vpxm-498p](https://osv.dev/vulnerability/GHSA-6rw7-vpxm-498p) | CVE-2025-15284 | 3.7 | 0.4% (39%) | No | 6.14.1 | CVSS 3.7, EPSS 0.45% |
| P4 | axios 0.21.0 | [GHSA-mmx7-hfxf-jppx](https://osv.dev/vulnerability/GHSA-mmx7-hfxf-jppx) | CVE-2026-67316 | 5.5 | 0.4% (37%) | No | 0.33.0 | CVSS 5.5, EPSS 0.42% |
| P4 | qs 6.7.0 | [GHSA-4mjr-xmp4-gh2g](https://osv.dev/vulnerability/GHSA-4mjr-xmp4-gh2g) | CVE-2026-82417 | 5.3 | 0.4% (34%) | No | 6.16.0 | CVSS 5.3, EPSS 0.40% |
| P4 | qs 6.7.0 | [GHSA-6pq8-jhm2-2vcw](https://osv.dev/vulnerability/GHSA-6pq8-jhm2-2vcw) | CVE-2026-110816 | 5.3 | 0.4% (31%) | No | 6.16.1 | CVSS 5.3, EPSS 0.37% |
| P4 | lodash 4.17.15 | [GHSA-f23m-r3pf-42rh](https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh) | CVE-2026-2950 | 6.5 | 0.3% (27%) | No | 4.18.0 | CVSS 6.5, EPSS 0.34% |
| P4 | axios 0.21.0 | [GHSA-898c-q2cr-xwhg](https://osv.dev/vulnerability/GHSA-898c-q2cr-xwhg) | CVE-2026-44490 | 4.8 | 0.3% (26%) | No | 0.32.0 | CVSS 4.8, EPSS 0.33% |
| P4 | axios 0.21.0 | [GHSA-5c9x-8gcm-mpgx](https://osv.dev/vulnerability/GHSA-5c9x-8gcm-mpgx) | CVE-2026-42034 | 5.3 | 0.3% (26%) | No | 0.31.1 | CVSS 5.3, EPSS 0.33% |
| P4 | axios 0.21.0 | [GHSA-vf2m-468p-8v99](https://osv.dev/vulnerability/GHSA-vf2m-468p-8v99) | CVE-2026-42036 | 5.3 | 0.3% (26%) | No | 0.31.1 | CVSS 5.3, EPSS 0.33% |
| P4 | axios 0.21.0 | [GHSA-m7pr-hjqh-92cm](https://osv.dev/vulnerability/GHSA-m7pr-hjqh-92cm) | CVE-2026-42038 | 6.8 | 0.3% (25%) | No | 0.31.1 | CVSS 6.8, EPSS 0.32% |
| P4 | axios 0.21.0 | [GHSA-7q8q-rj6j-mhjq](https://osv.dev/vulnerability/GHSA-7q8q-rj6j-mhjq) | CVE-2026-67319 | 5.5 | 0.3% (25%) | No | 0.33.0 | CVSS 5.5, EPSS 0.32% |
| P4 | axios 0.21.0 | [GHSA-xhjh-pmcv-23jw](https://osv.dev/vulnerability/GHSA-xhjh-pmcv-23jw) | CVE-2026-42040 | 3.7 | 0.2% (12%) | No | 0.31.1 | CVSS 3.7, EPSS 0.22% |
| P4 | axios 0.21.0 | [GHSA-xx6v-rp6x-q39c](https://osv.dev/vulnerability/GHSA-xx6v-rp6x-q39c) | CVE-2026-42042 | 5.4 | 0.2% (11%) | No | 0.31.1 | CVSS 5.4, EPSS 0.21% |

---
_Live scan run in GitHub Actions on 3 November 2026. Results change as new vulnerabilities and EPSS scores are published._

Data: [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/). EPSS is the probability of exploitation activity in the next 30 days.=====END live/npm_report.md
