# Vulnerability priority report: `requirements.txt`

Scanned **11** packages and found **177** known vulnerabilities.

> **99** are rated High or Critical by CVSS alone. After adding real-world exploitation data, **12** need fixing now, cutting urgent work by **88%**.

| Tier | Meaning | Count |
|---|---|---|
| **P1** | Fix now (days): exploited in the wild, or likely to be exploited and severe | 12 |
| **P2** | Fix soon (weeks): likely to be exploited, or critical severity | 15 |
| **P3** | Plan (next release): high severity or some exploitation likelihood | 97 |
| **P4** | Backlog: low likelihood and lower severity | 53 |

## Upgrade plan

| Package | Current | Upgrade to | Vulns fixed | Worst tier |
|---|---|---|---|---|
| cryptography | 3.2 | **49.0.0** | 16 | P1 |
| django | 3.2.0 | **5.2.17** | 38 | P1 |
| pillow | 8.0.0 | **13.0.0** | 70 | P1 |
| werkzeug | 0.15.3 | **3.1.9** | 11 | P1 |
| pyyaml | 5.3 | **5.4** | 2 | P2 |
| flask | 0.12.2 | **3.1.3** | 4 | P3 |
| jinja2 | 2.10 | **3.1.6** | 6 | P3 |
| paramiko | 2.4.1 | **2.9.3** | 2 (1 without fix) | P3 |
| requests | 2.19.1 | **2.33.0** | 5 | P3 |
| sqlparse | 0.4.1 | **0.6.0** | 9 | P3 |
| urllib3 | 1.24.1 | **2.8.0** | 13 | P3 |

## All findings

| Tier | Package | Advisory | CVE | CVSS | EPSS (percentile) | KEV | Fixed in | Why this tier |
|---|---|---|---|---|---|---|---|---|
| P1 | pillow 8.0.0 | [GHSA-j7hp-h8jx-5ppr](https://osv.dev/vulnerability/GHSA-j7hp-h8jx-5ppr) | CVE-2023-4863, CVE-2023-5129 | 8.8 | 100.0% (100%) | **Yes** | 10.0.1 | listed in CISA KEV (known exploited) |
| P1 | django 3.2.0 | [GHSA-p64x-8rxx-wf6q](https://osv.dev/vulnerability/GHSA-p64x-8rxx-wf6q) | CVE-2022-34265 | 9.8 | 73.6% (99%) | No | 3.2.14 | EPSS 73.6% and CVSS 9.8 |
| P1 | cryptography 3.2 | [GHSA-x4qr-2fvf-3mr5](https://osv.dev/vulnerability/GHSA-x4qr-2fvf-3mr5) | CVE-2023-0286 | 7.4 | 69.3% (99%) | No | 39.0.1 | EPSS 69.3% and CVSS 7.4 |
| P1 | django 3.2.0 | [GHSA-2hrw-hx67-34x6](https://osv.dev/vulnerability/GHSA-2hrw-hx67-34x6) | CVE-2023-24580 | 7.5 | 62.6% (99%) | No | 3.2.18 | EPSS 62.6% and CVSS 7.5 |
| P1 | werkzeug 0.15.3 | [GHSA-j544-7q9p-6xp8](https://osv.dev/vulnerability/GHSA-j544-7q9p-6xp8) | CVE-2019-14322 | 7.5 | 55.8% (99%) | No | 0.15.5 | EPSS 55.8% and CVSS 7.5 |
| P1 | django 3.2.0 | [GHSA-qmf9-6jqf-j8fq](https://osv.dev/vulnerability/GHSA-qmf9-6jqf-j8fq) | CVE-2023-46695 | 7.5 | 53.4% (99%) | No | 3.2.23 | EPSS 53.4% and CVSS 7.5 |
| P1 | django 3.2.0 | [GHSA-6cw3-g6wv-c2xv](https://osv.dev/vulnerability/GHSA-6cw3-g6wv-c2xv) | CVE-2022-23833 | 7.5 | 49.5% (99%) | No | 3.2.12 | EPSS 49.5% and CVSS 7.5 |
| P1 | django 3.2.0 | [GHSA-q2jf-h9jm-m7p4](https://osv.dev/vulnerability/GHSA-q2jf-h9jm-m7p4) | CVE-2023-23969 | 7.5 | 47.4% (99%) | No | 3.2.17 | EPSS 47.4% and CVSS 7.5 |
| P1 | django 3.2.0 | [GHSA-xpfp-f569-q3p2](https://osv.dev/vulnerability/GHSA-xpfp-f569-q3p2) | CVE-2021-35042 | 9.8 | 44.4% (99%) | No | 3.2.5 | EPSS 44.4% and CVSS 9.8 |
| P1 | django 3.2.0 | [GHSA-6w2r-r2m5-xq5w](https://osv.dev/vulnerability/GHSA-6w2r-r2m5-xq5w) | CVE-2025-57833 | 7.1 | 26.1% (98%) | No | 4.2.24 | EPSS 26.1% and CVSS 7.1 |
| P1 | django 3.2.0 | [GHSA-frmv-pr5f-9mcr](https://osv.dev/vulnerability/GHSA-frmv-pr5f-9mcr) | CVE-2025-64459 | 9.1 | 19.3% (97%) | No | 4.2.26 | EPSS 19.3% and CVSS 9.1 |
| P1 | django 3.2.0 | [GHSA-2gwj-7jmv-h26r](https://osv.dev/vulnerability/GHSA-2gwj-7jmv-h26r) | CVE-2022-28346 | 9.8 | 18.7% (97%) | No | 3.2.13 | EPSS 18.7% and CVSS 9.8 |
| P2 | cryptography 3.2 | [GHSA-rhm9-p9w5-fwm7](https://osv.dev/vulnerability/GHSA-rhm9-p9w5-fwm7) | CVE-2020-36242 | 9.1 | 6.8% (94%) | No | 3.3.2 | critical CVSS 9.1 |
| P2 | pyyaml 5.3 | [GHSA-8q59-q68h-6hv4](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) | CVE-2020-14343 | 9.8 | 6.0% (93%) | No | 5.4 | critical CVSS 9.8 |
| P2 | pyyaml 5.3 | [GHSA-6757-jp84-gxfx](https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx) | CVE-2020-1747 | 9.8 | 5.4% (93%) | No | 5.3.1 | critical CVSS 9.8 |
| P2 | pillow 8.0.0 | [GHSA-8vj2-vxx3-667w](https://osv.dev/vulnerability/GHSA-8vj2-vxx3-667w) | CVE-2022-22817 | 9.8 | 3.6% (89%) | No | 9.0.1 | critical CVSS 9.8 |
| P2 | pillow 8.0.0 | [GHSA-7534-mm45-c74v](https://osv.dev/vulnerability/GHSA-7534-mm45-c74v) | CVE-2021-34552 | 9.8 | 3.2% (88%) | No | 8.3.0 | critical CVSS 9.8 |
| P2 | django 3.2.0 | [GHSA-w24h-v9qh-8gxj](https://osv.dev/vulnerability/GHSA-w24h-v9qh-8gxj) | CVE-2022-28347 | 9.8 | 2.9% (87%) | No | 3.2.13 | critical CVSS 9.8 |
| P2 | pillow 8.0.0 | [GHSA-77gc-v2xv-rvvh](https://osv.dev/vulnerability/GHSA-77gc-v2xv-rvvh) | CVE-2021-25287 | 9.1 | 2.9% (87%) | No | 8.2.0 | critical CVSS 9.1 |
| P2 | pillow 8.0.0 | [GHSA-9j59-75qj-795w](https://osv.dev/vulnerability/GHSA-9j59-75qj-795w) | CVE-2022-24303 | 9.1 | 2.7% (86%) | No | 9.0.1 | critical CVSS 9.1 |
| P2 | pillow 8.0.0 | [GHSA-rwv7-3v45-hg29](https://osv.dev/vulnerability/GHSA-rwv7-3v45-hg29) | CVE-2021-25288 | 9.1 | 2.4% (84%) | No | 8.2.0 | critical CVSS 9.1 |
| P2 | pillow 8.0.0 | [GHSA-57h3-9rgr-c24m](https://osv.dev/vulnerability/GHSA-57h3-9rgr-c24m) | CVE-2021-25289 | 9.8 | 2.3% (84%) | No | 8.1.1 | critical CVSS 9.8 |
| P2 | django 3.2.0 | [GHSA-r3xc-prgr-mg9p](https://osv.dev/vulnerability/GHSA-r3xc-prgr-mg9p) | CVE-2023-31047 | 9.8 | 1.4% (72%) | No | 3.2.19 | critical CVSS 9.8 |
| P2 | pillow 8.0.0 | [GHSA-w889-685w-c8fh](https://osv.dev/vulnerability/GHSA-w889-685w-c8fh) | CVE-2026-112900 | 9.5 | 1.3% (71%) | No | 13.0.0 | critical CVSS 9.5 |
| P2 | pillow 8.0.0 | [GHSA-332p-7hrc-92wf](https://osv.dev/vulnerability/GHSA-332p-7hrc-92wf) | CVE-2026-112393 | 9.5 | 1.0% (63%) | No | 13.0.0 | critical CVSS 9.5 |
| P2 | pillow 8.0.0 | [GHSA-8g5g-8vmr-9782](https://osv.dev/vulnerability/GHSA-8g5g-8vmr-9782) | CVE-2026-112403 | 9.5 | 0.9% (61%) | No | 13.0.0 | critical CVSS 9.5 |
| P2 | pillow 8.0.0 | [GHSA-5x8w-8jj5-q52h](https://osv.dev/vulnerability/GHSA-5x8w-8jj5-q52h) | CVE-2026-112398 | 9.5 | 0.7% (53%) | No | 13.0.0 | critical CVSS 9.5 |
| P3 | werkzeug 0.15.3 | [PYSEC-2022-203](https://osv.dev/vulnerability/PYSEC-2022-203) | CVE-2022-29361 | - | 8.1% (95%) | No | 2.1.1 | CVSS 0.0, EPSS 8.07% |
| P3 | requests 2.19.1 | [GHSA-x84v-xcm2-53pg](https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg) | CVE-2018-18074 | 7.5 | 6.9% (94%) | No | 2.20.0 | CVSS 7.5, EPSS 6.93% |
| P3 | django 3.2.0 | [GHSA-rxjp-mfm9-w4wr](https://osv.dev/vulnerability/GHSA-rxjp-mfm9-w4wr) | CVE-2021-31542 | 7.5 | 5.3% (93%) | No | 3.2.1 | CVSS 7.5, EPSS 5.33% |
| P3 | django 3.2.0 | [GHSA-p99v-5w3c-jqq9](https://osv.dev/vulnerability/GHSA-p99v-5w3c-jqq9) | CVE-2021-33571 | 7.5 | 5.3% (93%) | No | 3.2.4 | CVSS 7.5, EPSS 5.26% |
| P3 | pillow 8.0.0 | [GHSA-3wvg-mj6g-m9cv](https://osv.dev/vulnerability/GHSA-3wvg-mj6g-m9cv) | CVE-2021-27922 | 7.5 | 4.9% (92%) | No | 8.1.2 | CVSS 7.5, EPSS 4.85% |
| P3 | paramiko 2.4.1 | [GHSA-f2j6-wrhh-v25m](https://osv.dev/vulnerability/GHSA-f2j6-wrhh-v25m) | CVE-2018-1000805 | 8.8 | 4.4% (91%) | No | 2.4.2 | CVSS 8.8, EPSS 4.41% |
| P3 | flask 0.12.2 | [GHSA-562c-5r94-xh97](https://osv.dev/vulnerability/GHSA-562c-5r94-xh97) | CVE-2018-1000656 | 7.5 | 3.9% (90%) | No | 0.12.3 | CVSS 7.5, EPSS 3.85% |
| P3 | django 3.2.0 | [GHSA-qrw5-5h28-6cmg](https://osv.dev/vulnerability/GHSA-qrw5-5h28-6cmg) | CVE-2022-41323 | 7.5 | 3.8% (90%) | No | 3.2.16 | CVSS 7.5, EPSS 3.75% |
| P3 | jinja2 2.10 | [GHSA-g3rq-g295-4j3m](https://osv.dev/vulnerability/GHSA-g3rq-g295-4j3m) | CVE-2020-28493 | 5.3 | 3.6% (89%) | No | 2.11.3 | CVSS 5.3, EPSS 3.59% |
| P3 | jinja2 2.10 | [GHSA-462w-v97r-4m45](https://osv.dev/vulnerability/GHSA-462w-v97r-4m45) | CVE-2019-10906 | 8.6 | 3.5% (89%) | No | 2.10.1 | CVSS 8.6, EPSS 3.53% |
| P3 | werkzeug 0.15.3 | [GHSA-2g68-c3qc-8985](https://osv.dev/vulnerability/GHSA-2g68-c3qc-8985) | CVE-2024-34069 | 7.5 | 3.4% (89%) | No | 3.0.3 | CVSS 7.5, EPSS 3.40% |
| P3 | django 3.2.0 | [GHSA-95rw-fx8r-36v6](https://osv.dev/vulnerability/GHSA-95rw-fx8r-36v6) | CVE-2022-22818 | 6.1 | 3.4% (89%) | No | 3.2.12 | CVSS 6.1, EPSS 3.36% |
| P3 | pillow 8.0.0 | [GHSA-98vv-pw6r-q6q4](https://osv.dev/vulnerability/GHSA-98vv-pw6r-q6q4) | CVE-2021-23437 | 7.5 | 3.2% (88%) | No | 8.3.2 | CVSS 7.5, EPSS 3.24% |
| P3 | sqlparse 0.4.1 | [GHSA-2m57-hf25-phgg](https://osv.dev/vulnerability/GHSA-2m57-hf25-phgg) | CVE-2024-4340 | 7.5 | 3.2% (88%) | No | 0.5.0 | CVSS 7.5, EPSS 3.24% |
| P3 | cryptography 3.2 | [GHSA-9v9h-cgj8-h64p](https://osv.dev/vulnerability/GHSA-9v9h-cgj8-h64p) | CVE-2024-0727 | 5.5 | 3.2% (88%) | No | 42.0.2 | CVSS 5.5, EPSS 3.19% |
| P3 | django 3.2.0 | [GHSA-qm57-vhq3-3fwf](https://osv.dev/vulnerability/GHSA-qm57-vhq3-3fwf) | CVE-2021-32052 | 6.1 | 3.2% (88%) | No | 3.2.2 | CVSS 6.1, EPSS 3.17% |
| P3 | pillow 8.0.0 | [GHSA-f4w8-cv6p-x6r5](https://osv.dev/vulnerability/GHSA-f4w8-cv6p-x6r5) | CVE-2021-27921 | 7.5 | 3.2% (88%) | No | 8.1.2 | CVSS 7.5, EPSS 3.17% |
| P3 | pillow 8.0.0 | [GHSA-95q3-8gr9-gm8w](https://osv.dev/vulnerability/GHSA-95q3-8gr9-gm8w) | CVE-2021-27923 | 7.5 | 3.0% (88%) | No | 8.1.2 | CVSS 7.5, EPSS 3.04% |
| P3 | django 3.2.0 | [GHSA-jh3w-4vvf-mjgr](https://osv.dev/vulnerability/GHSA-jh3w-4vvf-mjgr) | CVE-2023-36053 | 7.5 | 3.0% (87%) | No | 3.2.20 | CVSS 7.5, EPSS 2.98% |
| P3 | requests 2.19.1 | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) | CVE-2023-32681 | 6.1 | 3.0% (87%) | No | 2.31.0 | CVSS 6.1, EPSS 2.97% |
| P3 | urllib3 1.24.1 | [GHSA-38jv-5279-wg99](https://osv.dev/vulnerability/GHSA-38jv-5279-wg99) | CVE-2026-21441 | 7.5 | 2.9% (87%) | No | 2.6.3 | CVSS 7.5, EPSS 2.92% |
| P3 | urllib3 1.24.1 | [GHSA-mh33-7rrq-662w](https://osv.dev/vulnerability/GHSA-mh33-7rrq-662w) | CVE-2019-11324 | 7.5 | 2.9% (87%) | No | 1.24.2 | CVSS 7.5, EPSS 2.92% |
| P3 | pillow 8.0.0 | [GHSA-pw3c-h7wp-cvhx](https://osv.dev/vulnerability/GHSA-pw3c-h7wp-cvhx) | CVE-2022-22815 | 6.5 | 2.8% (86%) | No | 9.0.0 | CVSS 6.5, EPSS 2.77% |
| P3 | django 3.2.0 | [GHSA-68w8-qjq3-2gfm](https://osv.dev/vulnerability/GHSA-68w8-qjq3-2gfm) | CVE-2021-33203 | 4.9 | 2.7% (86%) | No | 3.2.4 | CVSS 4.9, EPSS 2.74% |
| P3 | django 3.2.0 | [GHSA-53qw-q765-4fww](https://osv.dev/vulnerability/GHSA-53qw-q765-4fww) | CVE-2021-45115 | 7.5 | 2.6% (85%) | No | 3.2.11 | CVSS 7.5, EPSS 2.60% |
| P3 | django 3.2.0 | [GHSA-jrh2-hc4r-7jwx](https://osv.dev/vulnerability/GHSA-jrh2-hc4r-7jwx) | CVE-2021-45452 | 5.3 | 2.6% (85%) | No | 3.2.11 | CVSS 5.3, EPSS 2.59% |
| P3 | pillow 8.0.0 | [GHSA-7r7m-5h27-29hp](https://osv.dev/vulnerability/GHSA-7r7m-5h27-29hp) | CVE-2021-28676 | 7.5 | 2.5% (85%) | No | 8.2.0 | CVSS 7.5, EPSS 2.50% |
| P3 | pillow 8.0.0 | [GHSA-q5hq-fp76-qmrc](https://osv.dev/vulnerability/GHSA-q5hq-fp76-qmrc) | CVE-2021-28677 | 7.5 | 2.5% (85%) | No | 8.2.0 | CVSS 7.5, EPSS 2.47% |
| P3 | cryptography 3.2 | [PYSEC-2021-62](https://osv.dev/vulnerability/PYSEC-2021-62) | CVE-2020-25659 | - | 2.5% (84%) | No | 3.2.1 | CVSS 0.0, EPSS 2.46% |
| P3 | django 3.2.0 | [GHSA-v6rh-hp5x-86rv](https://osv.dev/vulnerability/GHSA-v6rh-hp5x-86rv) | CVE-2021-44420 | 7.3 | 2.4% (84%) | No | 3.2.10 | CVSS 7.3, EPSS 2.42% |
| P3 | pillow 8.0.0 | [GHSA-8xjq-8fcg-g5hw](https://osv.dev/vulnerability/GHSA-8xjq-8fcg-g5hw) | CVE-2021-25290 | 7.5 | 2.4% (84%) | No | 8.1.1 | CVSS 7.5, EPSS 2.37% |
| P3 | sqlparse 0.4.1 | [GHSA-p5w8-wqhj-9hhf](https://osv.dev/vulnerability/GHSA-p5w8-wqhj-9hhf) | CVE-2021-32839 | 7.5 | 2.3% (84%) | No | 0.4.2 | CVSS 7.5, EPSS 2.34% |
| P3 | urllib3 1.24.1 | [GHSA-wqvq-5m8c-6g24](https://osv.dev/vulnerability/GHSA-wqvq-5m8c-6g24) | CVE-2020-26137 | 6.5 | 2.3% (83%) | No | 1.25.9 | CVSS 6.5, EPSS 2.27% |
| P3 | paramiko 2.4.1 | [PYSEC-2022-166](https://osv.dev/vulnerability/PYSEC-2022-166) | CVE-2022-24302 | - | 2.1% (82%) | No | 2.9.3 | CVSS 0.0, EPSS 2.08% |
| P3 | urllib3 1.24.1 | [GHSA-r64q-w8jr-g9qp](https://osv.dev/vulnerability/GHSA-r64q-w8jr-g9qp) | CVE-2019-11236 | 6.1 | 2.1% (81%) | No | 1.24.3 | CVSS 6.1, EPSS 2.07% |
| P3 | pillow 8.0.0 | [GHSA-xrcv-f9gm-v42c](https://osv.dev/vulnerability/GHSA-xrcv-f9gm-v42c) | CVE-2022-22816 | 6.5 | 2.1% (81%) | No | 9.0.0 | CVSS 6.5, EPSS 2.06% |
| P3 | django 3.2.0 | [GHSA-8c5j-9r9f-c6w8](https://osv.dev/vulnerability/GHSA-8c5j-9r9f-c6w8) | CVE-2021-45116 | 7.5 | 2.0% (81%) | No | 3.2.11 | CVSS 7.5, EPSS 1.98% |
| P3 | django 3.2.0 | [GHSA-qw25-v68c-qjf3](https://osv.dev/vulnerability/GHSA-qw25-v68c-qjf3) | CVE-2025-64458 | 7.5 | 1.9% (80%) | No | 4.2.26 | CVSS 7.5, EPSS 1.91% |
| P3 | pillow 8.0.0 | [GHSA-vqcj-wrf2-7v73](https://osv.dev/vulnerability/GHSA-vqcj-wrf2-7v73) | CVE-2020-35654 | 8.8 | 1.9% (79%) | No | 8.1.0 | CVSS 8.8, EPSS 1.87% |
| P3 | django 3.2.0 | [GHSA-vm8q-m57g-pff3](https://osv.dev/vulnerability/GHSA-vm8q-m57g-pff3) | CVE-2024-27351 | 5.3 | 1.9% (79%) | No | 3.2.25 | CVSS 5.3, EPSS 1.85% |
| P3 | flask 0.12.2 | [GHSA-5wv5-4vpf-pj6m](https://osv.dev/vulnerability/GHSA-5wv5-4vpf-pj6m) | CVE-2019-1010083 | 7.5 | 1.8% (79%) | No | 1.0 | CVSS 7.5, EPSS 1.83% |
| P3 | pillow 8.0.0 | [GHSA-9hx2-hgq2-2g4f](https://osv.dev/vulnerability/GHSA-9hx2-hgq2-2g4f) | CVE-2021-25292 | 6.5 | 1.7% (78%) | No | 8.1.1 | CVSS 6.5, EPSS 1.73% |
| P3 | pillow 8.0.0 | [GHSA-3f63-hfp8-52jq](https://osv.dev/vulnerability/GHSA-3f63-hfp8-52jq) | CVE-2023-50447 | 8.1 | 1.7% (77%) | No | 10.2.0 | CVSS 8.1, EPSS 1.70% |
| P3 | pillow 8.0.0 | [GHSA-hf64-x4gq-p99h](https://osv.dev/vulnerability/GHSA-hf64-x4gq-p99h) | CVE-2020-35655 | 5.4 | 1.7% (77%) | No | 8.1.0 | CVSS 5.4, EPSS 1.66% |
| P3 | pillow 8.0.0 | [GHSA-f5g8-5qq7-938w](https://osv.dev/vulnerability/GHSA-f5g8-5qq7-938w) | CVE-2020-35653 | 7.1 | 1.6% (76%) | No | 8.1.0 | CVSS 7.1, EPSS 1.64% |
| P3 | django 3.2.0 | [GHSA-xxj9-f6rv-m3x4](https://osv.dev/vulnerability/GHSA-xxj9-f6rv-m3x4) | CVE-2024-24680 | 5.9 | 1.6% (76%) | No | 3.2.24 | CVSS 5.9, EPSS 1.61% |
| P3 | pillow 8.0.0 | [GHSA-p43w-g3c5-g5mq](https://osv.dev/vulnerability/GHSA-p43w-g3c5-g5mq) | CVE-2021-25293 | 7.5 | 1.6% (76%) | No | 8.1.1 | CVSS 7.5, EPSS 1.60% |
| P3 | django 3.2.0 | [GHSA-7h4p-27mh-hmrw](https://osv.dev/vulnerability/GHSA-7h4p-27mh-hmrw) | CVE-2023-41164 | 5.3 | 1.5% (75%) | No | 3.2.21 | CVSS 5.3, EPSS 1.52% |
| P3 | django 3.2.0 | [GHSA-h8gc-pgj2-vjm3](https://osv.dev/vulnerability/GHSA-h8gc-pgj2-vjm3) | CVE-2023-43665 | 5.9 | 1.5% (74%) | No | 3.2.22 | CVSS 5.9, EPSS 1.46% |
| P3 | werkzeug 0.15.3 | [GHSA-xg9f-g7g7-2323](https://osv.dev/vulnerability/GHSA-xg9f-g7g7-2323) | CVE-2023-25577 | 7.5 | 1.4% (73%) | No | 2.2.3 | CVSS 7.5, EPSS 1.42% |
| P3 | pillow 8.0.0 | [GHSA-mvg9-xffr-p774](https://osv.dev/vulnerability/GHSA-mvg9-xffr-p774) | CVE-2021-25291 | 7.5 | 1.4% (72%) | No | 8.2.0 | CVSS 7.5, EPSS 1.40% |
| P3 | urllib3 1.24.1 | [GHSA-v845-jxx5-vc9f](https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f) | CVE-2023-43804 | 5.9 | 1.4% (72%) | No | 1.26.17 | CVSS 5.9, EPSS 1.36% |
| P3 | pillow 8.0.0 | [GHSA-8ghj-p4vj-mr35](https://osv.dev/vulnerability/GHSA-8ghj-p4vj-mr35) | CVE-2023-44271 | 7.5 | 1.3% (71%) | No | 10.0.0 | CVSS 7.5, EPSS 1.35% |
| P3 | pillow 8.0.0 | [GHSA-m2vv-5vj5-2hm7](https://osv.dev/vulnerability/GHSA-m2vv-5vj5-2hm7) | CVE-2022-45198 | 7.5 | 1.3% (70%) | No | 9.2.0 | CVSS 7.5, EPSS 1.30% |
| P3 | cryptography 3.2 | [GHSA-w7pp-m8wf-vj6r](https://osv.dev/vulnerability/GHSA-w7pp-m8wf-vj6r) | CVE-2023-23931 | 6.5 | 1.3% (70%) | No | 39.0.1 | CVSS 6.5, EPSS 1.30% |
| P3 | werkzeug 0.15.3 | [PYSEC-2023-221](https://osv.dev/vulnerability/PYSEC-2023-221) | CVE-2023-46136 | 7.5 | 1.3% (70%) | No | 2.3.8 | CVSS 7.5, EPSS 1.29% |
| P3 | flask 0.12.2 | [GHSA-m2qf-hxjv-5gpq](https://osv.dev/vulnerability/GHSA-m2qf-hxjv-5gpq) | CVE-2023-30861 | 7.5 | 1.2% (69%) | No | 2.2.5 | CVSS 7.5, EPSS 1.25% |
| P3 | pillow 8.0.0 | [PYSEC-2022-42980](https://osv.dev/vulnerability/PYSEC-2022-42980) | CVE-2022-45199 | - | 1.2% (68%) | No | 9.3.0 | CVSS 0.0, EPSS 1.21% |
| P3 | urllib3 1.24.1 | [GHSA-34jh-p97f-mpxf](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf) | CVE-2024-37891 | 4.4 | 1.1% (67%) | No | 1.26.19 | CVSS 4.4, EPSS 1.14% |
| P3 | django 3.2.0 | [GHSA-wvqv-fj8w-qmhm](https://osv.dev/vulnerability/GHSA-wvqv-fj8w-qmhm) | CVE-2026-15307 | 8.8 | 1.1% (66%) | No | 5.2.17 | CVSS 8.8, EPSS 1.13% |
| P3 | cryptography 3.2 | [GHSA-3ww4-gg4f-jr7f](https://osv.dev/vulnerability/GHSA-3ww4-gg4f-jr7f) | CVE-2023-50782 | 7.5 | 1.1% (66%) | No | 42.0.0 | CVSS 7.5, EPSS 1.12% |
| P3 | django 3.2.0 | [GHSA-q238-5cxm-5c9h](https://osv.dev/vulnerability/GHSA-q238-5cxm-5c9h) | CVE-2026-15830 | 5.3 | 1.1% (66%) | No | 5.2.17 | CVSS 5.3, EPSS 1.11% |
| P3 | django 3.2.0 | [GHSA-8x94-hmjh-97hq](https://osv.dev/vulnerability/GHSA-8x94-hmjh-97hq) | CVE-2022-36359 | 8.8 | 0.9% (61%) | No | 3.2.15 | CVSS 8.8, EPSS 0.94% |
| P3 | cryptography 3.2 | [PYSEC-2024-225](https://osv.dev/vulnerability/PYSEC-2024-225) | CVE-2024-26130 | 7.5 | 0.8% (58%) | No | 42.0.4 | CVSS 7.5, EPSS 0.83% |
| P3 | urllib3 1.24.1 | [GHSA-2xpw-w6gg-jr37](https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37) | CVE-2025-66471 | 7.5 | 0.7% (52%) | No | 2.6.0 | CVSS 7.5, EPSS 0.68% |
| P3 | urllib3 1.24.1 | [GHSA-gm62-xv2j-4w53](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53) | CVE-2025-66418 | 7.5 | 0.7% (52%) | No | 2.6.0 | CVSS 7.5, EPSS 0.68% |
| P3 | pillow 8.0.0 | [GHSA-mrfp-p49p-3hf2](https://osv.dev/vulnerability/GHSA-mrfp-p49p-3hf2) | CVE-2026-96640 | 7.5 | 0.6% (49%) | No | 13.0.0 | CVSS 7.5, EPSS 0.60% |
| P3 | pillow 8.0.0 | [GHSA-7mwm-ghpf-9vrm](https://osv.dev/vulnerability/GHSA-7mwm-ghpf-9vrm) | CVE-2026-112402 | 7.5 | 0.6% (48%) | No | 13.0.0 | CVSS 7.5, EPSS 0.59% |
| P3 | pillow 8.0.0 | [GHSA-jg86-v3jv-hrpm](https://osv.dev/vulnerability/GHSA-jg86-v3jv-hrpm) | CVE-2026-112894 | 7.5 | 0.6% (48%) | No | 13.0.0 | CVSS 7.5, EPSS 0.59% |
| P3 | pillow 8.0.0 | [GHSA-p4wg-p73j-c528](https://osv.dev/vulnerability/GHSA-p4wg-p73j-c528) | CVE-2026-112895 | 7.5 | 0.6% (48%) | No | 13.0.0 | CVSS 7.5, EPSS 0.59% |
| P3 | pillow 8.0.0 | [GHSA-22hg-r758-rrw9](https://osv.dev/vulnerability/GHSA-22hg-r758-rrw9) | CVE-2026-112390 | 7.5 | 0.6% (48%) | No | 13.0.0 | CVSS 7.5, EPSS 0.59% |
| P3 | pillow 8.0.0 | [GHSA-27h8-gf7j-v5hc](https://osv.dev/vulnerability/GHSA-27h8-gf7j-v5hc) | CVE-2026-112392 | 7.5 | 0.6% (48%) | No | 13.0.0 | CVSS 7.5, EPSS 0.59% |
| P3 | pillow 8.0.0 | [GHSA-58r4-6rv3-gfh8](https://osv.dev/vulnerability/GHSA-58r4-6rv3-gfh8) | CVE-2026-112397 | 7.5 | 0.6% (47%) | No | 13.0.0 | CVSS 7.5, EPSS 0.57% |
| P3 | pillow 8.0.0 | [GHSA-f2g6-542v-9j58](https://osv.dev/vulnerability/GHSA-f2g6-542v-9j58) | CVE-2026-112406 | 7.5 | 0.6% (47%) | No | 13.0.0 | CVSS 7.5, EPSS 0.57% |
| P3 | jinja2 2.10 | [GHSA-q2x7-8rv6-6q7h](https://osv.dev/vulnerability/GHSA-q2x7-8rv6-6q7h) | CVE-2024-56326 | 7.8 | 0.5% (44%) | No | 3.1.5 | CVSS 7.8, EPSS 0.52% |
| P3 | pillow 8.0.0 | [GHSA-45hq-cxwh-f6vc](https://osv.dev/vulnerability/GHSA-45hq-cxwh-f6vc) | CVE-2026-55379 | 7.5 | 0.5% (44%) | No | 12.3.0 | CVSS 7.5, EPSS 0.52% |
| P3 | pillow 8.0.0 | [GHSA-62p4-gmf7-7g93](https://osv.dev/vulnerability/GHSA-62p4-gmf7-7g93) | CVE-2026-54058 | 7.5 | 0.5% (44%) | No | 12.3.0 | CVSS 7.5, EPSS 0.52% |
| P3 | pillow 8.0.0 | [GHSA-phj9-mv4w-65pm](https://osv.dev/vulnerability/GHSA-phj9-mv4w-65pm) | CVE-2026-55380 | 7.5 | 0.5% (44%) | No | 12.3.0 | CVSS 7.5, EPSS 0.52% |
| P3 | pillow 8.0.0 | [GHSA-gg2r-wvfm-q9rx](https://osv.dev/vulnerability/GHSA-gg2r-wvfm-q9rx) | CVE-2026-112892 | 7.5 | 0.5% (43%) | No | 13.0.0 | CVSS 7.5, EPSS 0.50% |
| P3 | pillow 8.0.0 | [GHSA-q45j-58j2-45rg](https://osv.dev/vulnerability/GHSA-q45j-58j2-45rg) | CVE-2026-112897 | 7.5 | 0.5% (41%) | No | 13.0.0 | CVSS 7.5, EPSS 0.48% |
| P3 | pillow 8.0.0 | [GHSA-pchr-8j38-3x4p](https://osv.dev/vulnerability/GHSA-pchr-8j38-3x4p) | CVE-2026-112896 | 7.5 | 0.5% (41%) | No | 13.0.0 | CVSS 7.5, EPSS 0.47% |
| P3 | pillow 8.0.0 | [GHSA-xj96-63gp-2gmr](https://osv.dev/vulnerability/GHSA-xj96-63gp-2gmr) | CVE-2026-59197 | 8.2 | 0.4% (39%) | No | 12.3.0 | CVSS 8.2, EPSS 0.45% |
| P3 | pillow 8.0.0 | [GHSA-5x94-69rx-g8h2](https://osv.dev/vulnerability/GHSA-5x94-69rx-g8h2) | CVE-2026-54060 | 7.5 | 0.4% (36%) | No | 12.3.0 | CVSS 7.5, EPSS 0.42% |
| P3 | pillow 8.0.0 | [GHSA-8v84-f9pq-wr9x](https://osv.dev/vulnerability/GHSA-8v84-f9pq-wr9x) | CVE-2026-54059 | 7.5 | 0.4% (35%) | No | 12.3.0 | CVSS 7.5, EPSS 0.41% |
| P3 | cryptography 3.2 | [GHSA-r6ph-v2qm-q3c2](https://osv.dev/vulnerability/GHSA-r6ph-v2qm-q3c2) | CVE-2026-26007 | 7.5 | 0.4% (33%) | No | 46.0.5 | CVSS 7.5, EPSS 0.39% |
| P3 | pillow 8.0.0 | [GHSA-6r8x-57c9-28j4](https://osv.dev/vulnerability/GHSA-6r8x-57c9-28j4) | CVE-2026-59199 | 7.5 | 0.4% (33%) | No | 12.3.0 | CVSS 7.5, EPSS 0.39% |
| P3 | pillow 8.0.0 | [GHSA-9hw9-ch79-4vh6](https://osv.dev/vulnerability/GHSA-9hw9-ch79-4vh6) | CVE-2026-59205 | 7.5 | 0.4% (33%) | No | 12.3.0 | CVSS 7.5, EPSS 0.39% |
| P3 | pillow 8.0.0 | [GHSA-jjj6-mw9f-p565](https://osv.dev/vulnerability/GHSA-jjj6-mw9f-p565) | CVE-2026-59200 | 7.5 | 0.4% (33%) | No | 12.3.0 | CVSS 7.5, EPSS 0.39% |
| P3 | pillow 8.0.0 | [GHSA-9v9v-9qvf-h2hj](https://osv.dev/vulnerability/GHSA-9v9v-9qvf-h2hj) | CVE-2026-96644 | 7.5 | 0.4% (32%) | No | 13.0.0 | CVSS 7.5, EPSS 0.38% |
| P3 | pillow 8.0.0 | [GHSA-g842-9rc4-69pw](https://osv.dev/vulnerability/GHSA-g842-9rc4-69pw) | CVE-2026-96637 | 7.5 | 0.4% (31%) | No | 13.0.0 | CVSS 7.5, EPSS 0.37% |
| P3 | pillow 8.0.0 | [GHSA-3j72-p6qg-6xp7](https://osv.dev/vulnerability/GHSA-3j72-p6qg-6xp7) | CVE-2026-96642 | 7.5 | 0.3% (28%) | No | 13.0.0 | CVSS 7.5, EPSS 0.34% |
| P3 | sqlparse 0.4.1 | [GHSA-prg7-hcfm-mfcr](https://osv.dev/vulnerability/GHSA-prg7-hcfm-mfcr) | CVE-2026-59893 | 7.5 | 0.3% (27%) | No | 0.6.0 | CVSS 7.5, EPSS 0.34% |
| P3 | urllib3 1.24.1 | [GHSA-vxq7-64xx-v4gw](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw) | CVE-2026-97689 | 7.5 | 0.3% (27%) | No | 2.8.0 | CVSS 7.5, EPSS 0.34% |
| P3 | sqlparse 0.4.1 | [GHSA-pwgv-4x5q-6m9f](https://osv.dev/vulnerability/GHSA-pwgv-4x5q-6m9f) | CVE-2026-54284 | 7.5 | 0.3% (26%) | No | 0.6.0 | CVSS 7.5, EPSS 0.33% |
| P3 | sqlparse 0.4.1 | [GHSA-f2ff-p2ww-7p4p](https://osv.dev/vulnerability/GHSA-f2ff-p2ww-7p4p) | CVE-2026-71491 | 7.5 | 0.3% (18%) | No | 0.6.0 | CVSS 7.5, EPSS 0.26% |
| P3 | pillow 8.0.0 | [GHSA-xvh5-g6gv-559v](https://osv.dev/vulnerability/GHSA-xvh5-g6gv-559v) | CVE-2026-112902 | 7.5 | - | No | 13.0.0 | CVSS 7.5, EPSS 0.00% |
| P3 | cryptography 3.2 | [GHSA-537c-gmf6-5ccf](https://osv.dev/vulnerability/GHSA-537c-gmf6-5ccf) | - | 7.5 | - | No | 48.0.1 | CVSS 7.5, EPSS 0.00% |
| P4 | pillow 8.0.0 | [GHSA-44wm-f244-xhp3](https://osv.dev/vulnerability/GHSA-44wm-f244-xhp3) | CVE-2024-28219 | 6.7 | 1.0% (63%) | No | 10.3.0 | CVSS 6.7, EPSS 1.00% |
| P4 | cryptography 3.2 | [GHSA-jfhm-5ghh-2f97](https://osv.dev/vulnerability/GHSA-jfhm-5ghh-2f97) | CVE-2023-49083 | 5.9 | 1.0% (62%) | No | 41.0.6 | CVSS 5.9, EPSS 0.98% |
| P4 | sqlparse 0.4.1 | [GHSA-rrm6-wvj7-cwh2](https://osv.dev/vulnerability/GHSA-rrm6-wvj7-cwh2) | CVE-2023-30608 | 5.5 | 1.0% (62%) | No | 0.4.4 | CVSS 5.5, EPSS 0.98% |
| P4 | requests 2.19.1 | [GHSA-9hjg-9r4m-mvj7](https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7) | CVE-2024-47081 | 5.3 | 1.0% (62%) | No | 2.32.4 | CVSS 5.3, EPSS 0.98% |
| P4 | jinja2 2.10 | [GHSA-h75v-3vvj-5mfj](https://osv.dev/vulnerability/GHSA-h75v-3vvj-5mfj) | CVE-2024-34064 | 5.4 | 1.0% (62%) | No | 3.1.4 | CVSS 5.4, EPSS 0.98% |
| P4 | pillow 8.0.0 | [GHSA-g6rj-rv7j-xwp4](https://osv.dev/vulnerability/GHSA-g6rj-rv7j-xwp4) | CVE-2021-28675 | 5.5 | 1.0% (61%) | No | 8.2.0 | CVSS 5.5, EPSS 0.96% |
| P4 | jinja2 2.10 | [GHSA-h5c8-rqwp-cp95](https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95) | CVE-2024-22195 | 5.4 | 0.9% (59%) | No | 3.1.3 | CVSS 5.4, EPSS 0.89% |
| P4 | django 3.2.0 | [GHSA-7xr5-9hcq-chf9](https://osv.dev/vulnerability/GHSA-7xr5-9hcq-chf9) | CVE-2025-48432 | 4.0 | 0.8% (57%) | No | 4.2.22 | CVSS 4.0, EPSS 0.81% |
| P4 | django 3.2.0 | [GHSA-rrqc-c2jx-6jgv](https://osv.dev/vulnerability/GHSA-rrqc-c2jx-6jgv) | CVE-2024-45231 | 3.7 | 0.8% (56%) | No | 4.2.16 | CVSS 3.7, EPSS 0.79% |
| P4 | werkzeug 0.15.3 | [GHSA-f9vj-2wh5-fj8j](https://osv.dev/vulnerability/GHSA-f9vj-2wh5-fj8j) | CVE-2024-49766 | 5.5 | 0.8% (56%) | No | 3.0.6 | CVSS 5.5, EPSS 0.78% |
| P4 | pillow 8.0.0 | [GHSA-hjfx-8p6c-g7gx](https://osv.dev/vulnerability/GHSA-hjfx-8p6c-g7gx) | CVE-2021-28678 | 5.5 | 0.7% (54%) | No | 8.2.0 | CVSS 5.5, EPSS 0.73% |
| P4 | pillow 8.0.0 | [GHSA-74r2-7ff9-mjj2](https://osv.dev/vulnerability/GHSA-74r2-7ff9-mjj2) | CVE-2026-112401 | 5.5 | 0.6% (51%) | No | 13.0.0 | CVSS 5.5, EPSS 0.65% |
| P4 | werkzeug 0.15.3 | [GHSA-29vq-49wr-vm6x](https://osv.dev/vulnerability/GHSA-29vq-49wr-vm6x) | CVE-2026-27199 | 5.5 | 0.6% (50%) | No | 3.1.6 | CVSS 5.5, EPSS 0.63% |
| P4 | urllib3 1.24.1 | [GHSA-gwvm-45gx-3cf8](https://osv.dev/vulnerability/GHSA-gwvm-45gx-3cf8) | CVE-2018-25091 | 6.1 | 0.6% (48%) | No | 1.24.2 | CVSS 6.1, EPSS 0.59% |
| P4 | urllib3 1.24.1 | [GHSA-g4mx-q9vg-27p4](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4) | CVE-2023-45803 | 4.2 | 0.6% (48%) | No | 1.26.18 | CVSS 4.2, EPSS 0.59% |
| P4 | pillow 8.0.0 | [GHSA-254f-3936-288h](https://osv.dev/vulnerability/GHSA-254f-3936-288h) | CVE-2026-112391 | 5.5 | 0.6% (48%) | No | 13.0.0 | CVSS 5.5, EPSS 0.58% |
| P4 | pillow 8.0.0 | [GHSA-4558-3h8r-v8xp](https://osv.dev/vulnerability/GHSA-4558-3h8r-v8xp) | CVE-2026-112394 | 5.5 | 0.6% (46%) | No | 13.0.0 | CVSS 5.5, EPSS 0.56% |
| P4 | werkzeug 0.15.3 | [GHSA-hgf8-39gv-g3f2](https://osv.dev/vulnerability/GHSA-hgf8-39gv-g3f2) | CVE-2025-66221 | 5.5 | 0.5% (46%) | No | 3.1.4 | CVSS 5.5, EPSS 0.55% |
| P4 | pillow 8.0.0 | [GHSA-xgh8-jp6q-p5x8](https://osv.dev/vulnerability/GHSA-xgh8-jp6q-p5x8) | CVE-2026-112901 | 5.5 | 0.5% (45%) | No | 13.0.0 | CVSS 5.5, EPSS 0.53% |
| P4 | django 3.2.0 | [GHSA-crhf-3pfg-w68w](https://osv.dev/vulnerability/GHSA-crhf-3pfg-w68w) | CVE-2026-53877 | 4.8 | 0.5% (45%) | No | 5.2.16 | CVSS 4.8, EPSS 0.53% |
| P4 | jinja2 2.10 | [GHSA-cpwx-vrp4-4pq7](https://osv.dev/vulnerability/GHSA-cpwx-vrp4-4pq7) | CVE-2025-27516 | 5.5 | 0.5% (43%) | No | 3.1.6 | CVSS 5.5, EPSS 0.51% |
| P4 | werkzeug 0.15.3 | [GHSA-px8h-6qxv-m22q](https://osv.dev/vulnerability/GHSA-px8h-6qxv-m22q) | CVE-2023-23934 | 2.6 | 0.5% (43%) | No | 2.2.3 | CVSS 2.6, EPSS 0.51% |
| P4 | werkzeug 0.15.3 | [GHSA-87hc-h4r5-73f7](https://osv.dev/vulnerability/GHSA-87hc-h4r5-73f7) | CVE-2026-21860 | 5.3 | 0.5% (41%) | No | 3.1.5 | CVSS 5.3, EPSS 0.47% |
| P4 | urllib3 1.24.1 | [GHSA-pq67-6m6q-mj2v](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v) | CVE-2025-50181 | 5.3 | 0.5% (41%) | No | 2.5.0 | CVSS 5.3, EPSS 0.47% |
| P4 | django 3.2.0 | [GHSA-3h9f-r86x-qvjx](https://osv.dev/vulnerability/GHSA-3h9f-r86x-qvjx) | CVE-2026-48588 | 3.1 | 0.4% (37%) | No | 5.2.16 | CVSS 3.1, EPSS 0.43% |
| P4 | flask 0.12.2 | [GHSA-68rp-wp8r-4726](https://osv.dev/vulnerability/GHSA-68rp-wp8r-4726) | CVE-2026-27205 | 2.5 | 0.4% (34%) | No | 3.1.3 | CVSS 2.5, EPSS 0.40% |
| P4 | werkzeug 0.15.3 | [GHSA-g6x2-hccm-hh4m](https://osv.dev/vulnerability/GHSA-g6x2-hccm-hh4m) | CVE-2026-102598 | 5.5 | 0.4% (31%) | No | 3.1.9 | CVSS 5.5, EPSS 0.37% |
| P4 | django 3.2.0 | [GHSA-923m-gv2p-w5qp](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp) | CVE-2026-48587 | 3.1 | 0.4% (31%) | No | 5.2.15 | CVSS 3.1, EPSS 0.37% |
| P4 | pillow 8.0.0 | [GHSA-4rm8-3hmm-39fg](https://osv.dev/vulnerability/GHSA-4rm8-3hmm-39fg) | CVE-2026-96641 | 6.5 | 0.3% (28%) | No | 13.0.0 | CVSS 6.5, EPSS 0.34% |
| P4 | pillow 8.0.0 | [GHSA-p8hx-v2p6-rp84](https://osv.dev/vulnerability/GHSA-p8hx-v2p6-rp84) | CVE-2026-96636 | 6.5 | 0.3% (28%) | No | 13.0.0 | CVSS 6.5, EPSS 0.34% |
| P4 | requests 2.19.1 | [GHSA-9wx4-h78v-vm56](https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56) | CVE-2024-35195 | 5.6 | 0.3% (27%) | No | 2.32.0 | CVSS 5.6, EPSS 0.34% |
| P4 | urllib3 1.24.1 | [GHSA-qccp-gfcp-xxvc](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc) | CVE-2026-44431 | 5.3 | 0.3% (26%) | No | 2.7.0 | CVSS 5.3, EPSS 0.33% |
| P4 | django 3.2.0 | [GHSA-8qcx-xf44-272x](https://osv.dev/vulnerability/GHSA-8qcx-xf44-272x) | CVE-2026-53878 | 6.1 | 0.3% (26%) | No | 5.2.16 | CVSS 6.1, EPSS 0.33% |
| P4 | pillow 8.0.0 | [GHSA-fj7v-r99m-22gq](https://osv.dev/vulnerability/GHSA-fj7v-r99m-22gq) | CVE-2026-59198 | 6.5 | 0.3% (24%) | No | 12.3.0 | CVSS 6.5, EPSS 0.31% |
| P4 | django 3.2.0 | [GHSA-8cjm-8mp7-r2xf](https://osv.dev/vulnerability/GHSA-8cjm-8mp7-r2xf) | CVE-2026-8404 | 3.1 | 0.3% (20%) | No | 5.2.15 | CVSS 3.1, EPSS 0.27% |
| P4 | cryptography 3.2 | [PYSEC-2026-3553](https://osv.dev/vulnerability/PYSEC-2026-3553) | CVE-2026-69249 | - | 0.3% (18%) | No | 49.0.0 | no CVSS score, low EPSS |
| P4 | django 3.2.0 | [GHSA-h7pc-vwp9-298g](https://osv.dev/vulnerability/GHSA-h7pc-vwp9-298g) | CVE-2026-6873 | 3.1 | 0.2% (16%) | No | 5.2.15 | CVSS 3.1, EPSS 0.24% |
| P4 | cryptography 3.2 | [PYSEC-2026-3554](https://osv.dev/vulnerability/PYSEC-2026-3554) | CVE-2026-69248 | - | 0.2% (16%) | No | 49.0.0 | no CVSS score, low EPSS |
| P4 | cryptography 3.2 | [GHSA-m959-cc7f-wv43](https://osv.dev/vulnerability/GHSA-m959-cc7f-wv43) | CVE-2026-34073 | 5.3 | 0.2% (13%) | No | 46.0.6 | CVSS 5.3, EPSS 0.23% |
| P4 | sqlparse 0.4.1 | [GHSA-cfqr-cjx5-5jcm](https://osv.dev/vulnerability/GHSA-cfqr-cjx5-5jcm) | CVE-2026-84305 | 5.5 | 0.2% (9%) | No | 0.6.0 | CVSS 5.5, EPSS 0.19% |
| P4 | requests 2.19.1 | [GHSA-gc5v-m9x4-r6x2](https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2) | CVE-2026-25645 | 4.4 | 0.2% (9%) | No | 2.33.0 | CVSS 4.4, EPSS 0.19% |
| P4 | pillow 8.0.0 | [GHSA-4x4j-2g7c-83w6](https://osv.dev/vulnerability/GHSA-4x4j-2g7c-83w6) | CVE-2026-55798 | 4.5 | 0.2% (7%) | No | 12.3.0 | CVSS 4.5, EPSS 0.18% |
| P4 | pillow 8.0.0 | [GHSA-r73j-pqj5-w3x7](https://osv.dev/vulnerability/GHSA-r73j-pqj5-w3x7) | CVE-2026-42310 | 5.5 | 0.2% (6%) | No | 12.2.0 | CVSS 5.5, EPSS 0.17% |
| P4 | sqlparse 0.4.1 | [GHSA-3496-9g83-7v6x](https://osv.dev/vulnerability/GHSA-3496-9g83-7v6x) | CVE-2026-59894 | 5.5 | 0.1% (3%) | No | 0.6.0 | CVSS 5.5, EPSS 0.13% |
| P4 | pillow 8.0.0 | [GHSA-wjx4-4jcj-g98j](https://osv.dev/vulnerability/GHSA-wjx4-4jcj-g98j) | CVE-2026-42308 | 5.5 | 0.1% (1%) | No | 12.2.0 | CVSS 5.5, EPSS 0.11% |
| P4 | paramiko 2.4.1 | [GHSA-r374-rxx8-8654](https://osv.dev/vulnerability/GHSA-r374-rxx8-8654) | CVE-2026-44405 | 3.4 | 0.1% (1%) | No | - | CVSS 3.4, EPSS 0.11% |
| P4 | pillow 8.0.0 | [GHSA-vx6w-vv9f-6gvg](https://osv.dev/vulnerability/GHSA-vx6w-vv9f-6gvg) | CVE-2026-112899 | 5.5 | - | No | 13.0.0 | CVSS 5.5, EPSS 0.00% |
| P4 | sqlparse 0.4.1 | [GHSA-27jp-wm6q-gp25](https://osv.dev/vulnerability/GHSA-27jp-wm6q-gp25) | - | 5.5 | - | No | 0.5.4 | CVSS 5.5, EPSS 0.00% |
| P4 | pillow 8.0.0 | [GHSA-4fx9-vc88-q2xc](https://osv.dev/vulnerability/GHSA-4fx9-vc88-q2xc) | - | 2.5 | - | No | 9.0.0 | CVSS 2.5, EPSS 0.00% |
| P4 | cryptography 3.2 | [GHSA-5cpq-8wj7-hf2v](https://osv.dev/vulnerability/GHSA-5cpq-8wj7-hf2v) | - | 2.5 | - | No | 41.0.0 | CVSS 2.5, EPSS 0.00% |
| P4 | cryptography 3.2 | [GHSA-jm77-qphf-c4w8](https://osv.dev/vulnerability/GHSA-jm77-qphf-c4w8) | - | 2.5 | - | No | 41.0.3 | CVSS 2.5, EPSS 0.00% |
| P4 | cryptography 3.2 | [GHSA-v8gr-m533-ghj9](https://osv.dev/vulnerability/GHSA-v8gr-m533-ghj9) | - | 2.5 | - | No | 41.0.4 | CVSS 2.5, EPSS 0.00% |
| P4 | pillow 8.0.0 | [PYSEC-2023-175](https://osv.dev/vulnerability/PYSEC-2023-175) | - | - | - | No | 10.0.1 | no CVSS score, low EPSS |

_Skipped 1 unpinned requirement(s): `numpy>=1.20`._

---
_Live scan run in GitHub Actions on 3 November 2026. Results change as new vulnerabilities and EPSS scores are published._

Data: [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/). EPSS is the probability of exploitation activity in the next 30 days.=====END live/requirements_report.md
with:
  name: live-reports
  path: project-05-vuln-prioritizer/live/
  if-no-files-found: warn
  compression-level: 6
  overwrite: false
  include-hidden-files: false
env:
  pythonLocation: /opt/hostedtoolcache/Python/3.12.15/x64
  PKG_CONFIG_PATH: /opt/hostedtoolcache/Python/3.12.15/x64/lib/pkgconfig
  Python_ROOT_DIR: /opt/hostedtoolcache/Python/3.12.15/x64
  Python2_ROOT_DIR: /opt/hostedtoolcache/Python/3.12.15/x64
  Python3_ROOT_DIR: /opt/hostedtoolcache/Python/3.12.15/x64
  LD_LIBRARY_PATH: /opt/hostedtoolcache/Python/3.12.15/x64/lib
##[endgroup]
(node:2339) [DEP0040] DeprecationWarning: The `punycode` module is deprecated. Please use a userland alternative instead.
(Use `node --trace-deprecation ...` to show where the warning was created)
With the provided path, there will be 4 files uploaded
Artifact name is valid!
Root directory input is valid!
Beginning upload of artifact content to blob storage
(node:2339) [DEP0169] DeprecationWarning: `url.parse()` behavior is not standardized and prone to errors that have security implications. Use the WHATWG URL API instead. CVEs are not issued for `url.parse()` vulnerabilities.
Uploaded bytes 30129
Finished uploading artifact content to blob storage!
SHA256 digest of uploaded artifact zip is ddc792b0466167c5955a4327021d504e20d413d85b05da879112e9806d17e01e
Finalizing artifact upload
Artifact live-reports.zip successfully finalized. Artifact ID 13215359598
Artifact live-reports has been successfully uploaded! Final size is 30129 bytes. Artifact ID is 13215359598
Artifact download URL: https://github.com/meerbaloch-security/cybersec-portfolio/actions/runs/41604903450/artifacts/13215359598
Post job cleanup.
(node:2351) [DEP0040] DeprecationWarning: The `punycode` module is deprecated. Please use a userland alternative instead.
(Use `node --trace-deprecation ...` to show where the warning was created)
Post job cleanup.
[command]/usr/bin/git version
git version 2.56.0
Temporarily overriding HOME='/home/runner/work/_temp/cabf3241-2e78-4161-939b-d386c2b5d8c5' before making global git config changes
Adding repository directory to the temporary git global config as a safe directory
[command]/usr/bin/git config --global --add safe.directory /home/runner/work/cybersec-portfolio/cybersec-portfolio
[command]/usr/bin/git config --local --name-only --get-regexp core\.sshCommand
[command]/usr/bin/git submodule foreach --recursive sh -c "git config --local --name-only --get-regexp 'core\.sshCommand' && git config --local --unset-all 'core.sshCommand' || :"
[command]/usr/bin/git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader
http.https://github.com/.extraheader
[command]/usr/bin/git config --local --unset-all http.https://github.com/.extraheader
[command]/usr/bin/git submodule foreach --recursive sh -c "git config --local --name-only --get-regexp 'http\.https\:\/\/github\.com\/\.extraheader' && git config --local --unset-all 'http.https://github.com/.extraheader' || :"
[command]/usr/bin/git config --local --name-only --get-regexp ^includeIf\.gitdir:
[command]/usr/bin/git submodule foreach --recursive git config --local --show-origin --name-only --get-regexp remote.origin.url
Cleaning up orphan processes
##[warning]Node.js 20 is deprecated. The following actions target Node.js 20 but are being forced to run on Node.js 24: actions/checkout@v4, actions/setup-python@v5, actions/upload-artifact@v4. For more information see: https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/
