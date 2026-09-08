"""
PrivEscGen: Multi-Agent Construction Pipeline for PrivEscalate.

Architecture:
    Manager Agent
    ├── Scaffolder Agent: Template → Dockerfile + setup.sh + Dockerfile.fixed
    ├── Exploiter Agent:  GTFOBins/Exploit-DB → exploit.sh (Retrieve > Adapt > Generate)
    └── Verifier Agent:   L1 Build + L2 Exploit Diff + L3 Consistency Check
"""

__version__ = "0.2.0"

from .manager import Manager as Manager, ScenarioSpec as ScenarioSpec
from .scaffolder import Scaffolder as Scaffolder
from .exploiter import Exploiter as Exploiter
from .verifier import Verifier as Verifier
from .ingester import DataIngester as DataIngester

__all__ = ["Manager", "ScenarioSpec", "Scaffolder", "Exploiter", "Verifier", "DataIngester"]
