"""Executable action descriptions shared by planning and capability discovery."""
from .models import SessionMode, StepAction
from .policy import _EXECUTABLE_ACTIONS


_DESCRIPTIONS = {
    "local_search": ("List local files", "List files in an approved directory; requires a path."),
    "summarize": ("Summarize", "Summarize supplied text or an approved file using the local model."),
    "draft": ("Draft text", "Generate text with the local model; an optional path creates a new output file."),
    "classify": ("Classify text", "Classify supplied text with the local model."),
    "report": ("Create report", "Read approved sources and generate text; an optional path creates a new output file."),
    "explain_security": ("Explain a decision", "Explain supplied decision context using the local model."),
    "read_file": ("Read a file", "Read a file inside the task's approved scope."),
    "write_file": ("Create a file", "Create a new file with the exact proposed content in an approved output scope."),
    "overwrite_file": ("Replace a file", "Replace an approved file with the exact proposed content."),
    "outbound_request": ("Request online data", "Send the reviewed method, destination and body through the airlock; approval required."),
}


def implemented_actions() -> frozenset[StepAction]:
    return frozenset(_EXECUTABLE_ACTIONS)


def action_catalog(mode: str) -> list[dict]:
    online = mode == SessionMode.ONLINE_ASSISTED.value
    return [
        {"action": action.value, "label": _DESCRIPTIONS[action.value][0], "description": _DESCRIPTIONS[action.value][1]}
        for action in sorted(implemented_actions(), key=lambda item: item.value)
        if action != StepAction.OUTBOUND_REQUEST or online
    ]


UNAVAILABLE_ACTIONS = [
    {"action": action.value, "reason": "No production executor is configured."}
    for action in StepAction if action not in _EXECUTABLE_ACTIONS
]
