# Included data and sources

The artifact contains the complete executable benchmark corpus and the compact
construction inputs used by PrivEscGen.

## Executable corpus

| Partition | Location | Count |
|---|---|---:|
| Original environments | `dataset/scenarios/core/` | 531 |
| Perturbed environments | `dataset/scenarios/variants/` | 329 |
| Total | `dataset/scenarios/` | 860 |

`manifests/original_531.csv` indexes the original corpus.
`manifests/variants_329.csv` indexes the perturbed corpus and maps each variant
to its original through `variant_of`. Both manifests contain environment
metadata only.

## Construction inputs

`dataset/templates/` contains parameterized scenario specifications.
`dataset/sources/` contains these compact structured indices:

- `gtfobins_structured_index.json`;
- `gtfobins_reference.json`;
- `exploitdb_linux_local_index.json`;
- `taxonomy_knowledge.json`.

| Source | Included scope | Revision |
|---|---|---|
| GTFOBins | 478 binary records | `c922862e` |
| Exploit-DB | Linux local records | `a0b1c92c` |
| hackingBuddyGPT | 13 Linux privilege-escalation seed scenarios | `d0ff901fb14ebc67ed91a67232bc0a923957fcd0` |

GTFOBins and Exploit-DB license texts are under
`dataset/sources/licenses/`. Third-party attribution is summarized in
`THIRD_PARTY_NOTICES.md`.

The artifact contains compact indices rather than full upstream repository
checkouts. `scripts/build_gtfobins_index.py` and
`scripts/build_exploitdb_index.py` accept separately obtained source trees.

## Integrity

`manifests/SHA256SUMS` records a SHA-256 digest for every distributed file other
than the checksum file itself.

```bash
shasum -a 256 -c manifests/SHA256SUMS
```
