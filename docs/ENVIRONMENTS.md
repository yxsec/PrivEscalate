# Evaluation environments

The artifact contains 860 Dockerized Linux privilege-escalation environments
with a uniform SSH and differential-verification interface.

## Corpus layout

`dataset/scenarios/core/` contains 531 original environments spanning the 14
benchmark sub-categories. `dataset/scenarios/variants/` contains 329 matched
perturbed environments. A perturbation changes surface details or adds
environmental distractors while preserving the intended escalation mechanism.

The corpus manifests are:

- `manifests/original_531.csv` for original environments;
- `manifests/variants_329.csv` for perturbed environments.

The `variant_of` column identifies the original corresponding to each variant.

## Environment contents

Every environment directory contains:

| File | Purpose |
|---|---|
| `Dockerfile` | Vulnerable environment |
| `Dockerfile.fixed` | Matched environment without the intended escalation path |
| `exploit.sh` | Ground-truth exploit for differential verification |
| `metadata.json` | Scenario ID, taxonomy, difficulty, and environment metadata |
| `run_config.json` | Container arguments, SSH settings, and startup timing |
| `verify.sh` | Vulnerable/fixed build and verification commands |

Two cron environments additionally contain `start.sh` for service startup.
Images are built locally from the supplied Dockerfiles when verification is run.

## Metadata

Scenario metadata identifies the ATT&CK technique, benchmark category,
difficulty, target user, intended vulnerability, exploitation steps, and fixed
configuration. Variant metadata additionally provides `variant_of` and the
perturbation description.

## Differential verification

From an environment directory:

```bash
docker build -t privescalate-test -f Dockerfile .
docker build -t privescalate-test-fixed -f Dockerfile.fixed .
bash verify.sh
```

The vulnerable image must allow `exploit.sh` to reach root. The fixed image
must reject the same escalation path.

## Safe execution

Run the environments only on an isolated host you control. Review
`run_config.json` before launch, bind exposed SSH ports to a local interface,
and do not expose benchmark containers to an untrusted network. Docker shares
the host kernel, so a dedicated evaluation machine is recommended.
