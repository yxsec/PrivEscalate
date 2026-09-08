# PrivEscalate

PrivEscalate is a Dockerized benchmark and agent suite for measuring
LLM-automated Linux privilege escalation. It provides an environment
construction system, a domain-specialized privilege-escalation agent, two
baseline agents, and 860 executable evaluation environments.

## Contents

- **PrivEscGen**: vulnerability ingestion, scenario scaffolding, exploit
  generation, differential verification, and construction prompts.
- **PrivEscAgent**: deterministic enumeration, category matching, strategy
  selection, step planning, and ReAct execution.
- **Baselines**: hackingBuddyGPT wintermute and HackSynth.
- **Original corpus**: 531 Dockerized environments across 14 Linux
  privilege-escalation sub-categories.
- **Perturbed corpus**: 329 matched variants that preserve the intended
  escalation mechanism while changing environmental details.
- **Evaluation interface**: common SSH runner, agent adapters, metrics,
  manifests, and environment verification scripts.

The repository contains the implementation code, executable environment
specifications, manifests, prompts, and evaluation entry points.

## Requirements

- Python 3.10--3.13 (the pinned native dependencies do not currently support
  Python 3.14);
- Docker with permission to build and run containers;
- an API key and endpoint for agent-backed evaluation.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and configure only the model providers you use.
The `.env` file is ignored by Git.

## Validate the artifact

These checks do not call an LLM or start Docker:

```bash
python scripts/validate_release.py
shasum -a 256 -c manifests/SHA256SUMS
python scripts/run_experiments.py --dry-run --agent privescagent --subset 2
```

## Verify an environment

```bash
cd dataset/scenarios/core/T1548_001_suid_find
bash verify.sh
```

`verify.sh` builds the vulnerable and fixed images, confirms that
`exploit.sh` reaches root in the vulnerable environment, and confirms that the
same escalation path fails in the fixed environment.

To process the complete corpus:

```bash
bash scripts/build_environments.sh --fixed
bash scripts/verify_environments.sh
```

## Run the agents

```bash
python scripts/run_experiments.py --agent wintermute --model gpt-4.1 --subset 1
python scripts/run_experiments.py --agent hacksynth --model gpt-4.1 --subset 1
python scripts/run_experiments.py --agent privescagent --model gpt-4.1 --subset 1
```

Provider variables and path overrides are documented in `.env.example`.
## Use PrivEscGen

```bash
python generate.py --list
python generate.py --template suid_gtfobins --provider openai
```

Construction prompts are packaged under `privescgen/prompts/`. Scenario
templates and compact source indices are under `dataset/templates/` and
`dataset/sources/`.

## Repository layout

```text
privescgen/                 PrivEscGen implementation and prompts
privescagent/               PrivEscAgent implementation and knowledge
baselines/                  wintermute and HackSynth source
evaluation/                 Common runner, metrics, and adapters
dataset/scenarios/core/     531 original environments
dataset/scenarios/variants/ 329 perturbed environments
dataset/templates/          PrivEscGen scenario templates
dataset/sources/            Compact construction indices and licenses
manifests/                  Corpus indexes and SHA-256 checksums
scripts/                    Construction, evaluation, and validation commands
docs/                       Final agent, data, and environment specifications
```

## Documentation

- `docs/ENVIRONMENTS.md`: corpus and environment interface;
- `docs/BASELINES.md`: PrivEscAgent and baseline interfaces;
- `docs/DATA_PROVENANCE.md`: included data, source revisions, and integrity.

## Citation

> Yixuan Liu, Zilong Zhen, Yin Wu, and Yi Li. 2026. PrivEscalate: Measuring
> and Augmenting the Threat of LLM-Automated Linux Privilege Escalation. In
> *Proceedings of the 2026 ACM SIGSAC Conference on Computer and
> Communications Security (CCS '26)*, November 15-19, 2026, The Hague,
> Netherlands. ACM, New York, NY, USA, 15 pages.
> https://doi.org/10.1145/3830454.3846719

Machine-readable citation metadata is available in `CITATION.cff`.

## Safety and licensing

Use PrivEscalate only on systems you own or are explicitly authorized to test.
The supplied exploits are intended for isolated benchmark containers. See
`ETHICS.md`.

No project-wide license is granted for the original PrivEscalate code and
data. Third-party components retain their licenses and attribution as listed
in `THIRD_PARTY_NOTICES.md`.
