"""
PrivEscAgent UseCase registration for hackingBuddyGPT.

Thin bridge: imports PrivEscAgentCore from the artifact project
and registers it as a hackingBuddyGPT UseCase.
"""

from hackingBuddyGPT.usecases.base import AutonomousAgentUseCase, use_case

try:
    from privescagent.agent import PrivEscAgentCore

    @use_case("PrivEscAgent: Domain-specialized Linux Privilege Escalation")
    class PrivEscAgentUseCase(AutonomousAgentUseCase[PrivEscAgentCore]):
        pass

except ImportError as e:
    # Importing privescagent.agent directly can transiently trigger this
    # bridge while that module is still initializing. The CLI imports
    # hackingBuddyGPT first and registers the bridge normally; do not emit a
    # misleading warning for the harmless direct-import cycle.
    if "partially initialized" not in str(e):
        import logging
        logging.getLogger(__name__).warning(
            f"PrivEscAgent unavailable: {e}. Run from the artifact root "
            "or add it to PYTHONPATH."
        )
