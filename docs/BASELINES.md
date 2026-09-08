# Agents and evaluation baselines

The artifact provides PrivEscAgent and two baseline agent architectures behind
the same scenario interface. Each agent connects to a low-privilege SSH shell,
issues Linux commands, and succeeds when the session reaches `uid=0` within the
configured step budget.

## PrivEscAgent

PrivEscAgent is the domain-specialized agent under `privescagent/`. It combines
a ReAct execution loop with four modules:

- PrivEnum performs deterministic Linux privilege-escalation enumeration;
- CategoryMatcher maps observations to vulnerability categories;
- StrategySelector ranks candidate escalation strategies;
- StepPlanner decomposes a strategy into verifiable actions.

Its evaluation adapter is `evaluation/adapters/privescagent_adapter.py`.

## wintermute

wintermute is the generic hackingBuddyGPT Linux privilege-escalation ReAct
baseline. Its source is under `baselines/hackingBuddyGPT/`, and its evaluation
adapter is `evaluation/adapters/wintermute.py`.

## HackSynth

HackSynth is the Planner-Summarizer baseline. The included `PentestAgent` is
under `baselines/HackSynth/`, and its SSH evaluation adapter is
`evaluation/adapters/hacksynth_adapter.py`.

## Common interface

The evaluation runner supplies every agent with the same target hostname,
SSH port, username, password, and step limit. The reported evaluation uses
zero-knowledge level 0: agents receive the SSH foothold and root-escalation
objective, but no vulnerability category, target binary, or exploit hint.

```bash
python scripts/run_experiments.py --agent wintermute --model gpt-4.1 --subset 1
python scripts/run_experiments.py --agent hacksynth --model gpt-4.1 --subset 1
python scripts/run_experiments.py --agent privescagent --model gpt-4.1 --subset 1
```

## Provider configuration

`.env.example` lists the supported API-key and endpoint variables. Secrets are
supplied at runtime through an ignored `.env` file or the process environment.
The artifact contains no API credentials or private endpoints.

The baseline licenses and upstream revisions are listed in
`THIRD_PARTY_NOTICES.md`.
