"""
PrivEscGen LLM Prompt Templates.

Each prompt is a dict with "system" and "user" keys.
User prompts contain {placeholder} variables for .format() substitution.

Prompt files:
  manager.py     - Manager Agent: parse vulnerability descriptions
  scaffolder.py  - Scaffolder Agent: generate/fix Dockerfiles, generate variants
  exploiter.py   - Exploiter Agent: generate/adapt exploit scripts
  verifier.py    - Verifier Agent: diagnose verification failures
"""

from .manager import MANAGER_PARSE_PROMPT
from .scaffolder import (
    SCAFFOLDER_ENV_PROMPT,
    SCAFFOLDER_FIX_PROMPT,
    SCAFFOLDER_VARIANT_PROMPT,
)
from .exploiter import (
    EXPLOITER_ADAPT_PROMPT,
    EXPLOITER_GENERATE_PROMPT,
)
from .verifier import VERIFIER_DIAGNOSE_PROMPT

__all__ = [
    "MANAGER_PARSE_PROMPT",
    "SCAFFOLDER_ENV_PROMPT",
    "SCAFFOLDER_FIX_PROMPT",
    "SCAFFOLDER_VARIANT_PROMPT",
    "EXPLOITER_ADAPT_PROMPT",
    "EXPLOITER_GENERATE_PROMPT",
    "VERIFIER_DIAGNOSE_PROMPT",
]
