"""User-facing risk explanations for native tool-action reviews."""

from typing import Protocol


class ToolActionRisk(Protocol):
    """Fields required to explain a native tool-action risk."""

    action_class: str
    reason: str


def tool_action_risk_summary(request: ToolActionRisk) -> str:
    """Describe both the action class and its concrete consequence."""

    if request.action_class.casefold() == "destructive shell command":
        return (
            "This destructive shell command can delete or overwrite local files, discard work, or alter "
            "repository or system state. Recovery may require version control or a backup."
        )
    return f"Sensitive native tool action ({request.action_class}): {request.reason.rstrip('.')}."
