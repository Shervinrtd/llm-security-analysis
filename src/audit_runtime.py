"""Runtime checks for interactive audits; research prompts remain unchanged."""
import json
import re


class ScanCancelled(Exception):
    """Cooperative cancellation at a safe boundary."""


class AnalysisError(Exception):
    """A check failed; it must not be represented as a negative finding."""


def check_cancel(event):
    if event is not None and event.is_set():
        raise ScanCancelled("Scan cancelled")


def checked_reply(provider, system, user, cancel_event=None):
    check_cancel(cancel_event)
    reply = provider.generate(system, user)
    check_cancel(cancel_event)
    if not reply.ok:
        # Provider error strings may contain URLs, credentials or source text.
        raise AnalysisError("Model request failed; check provider availability or quota.")
    if not reply.text or not reply.text.strip():
        raise AnalysisError("Model returned an empty answer.")
    return reply


def checked_object(text):
    """Read the final complete JSON object, allowing preceding reasoning/fences.

    Never salvage a truncated response or mistake an inner object for the answer.
    """
    decoder = json.JSONDecoder()
    fenced = list(re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S))
    if fenced and not text[fenced[-1].end():].strip():
        # A final explicit answer block takes precedence over braces in reasoning.
        text = fenced[-1].group(1)
    objects = []
    pos = 0
    while pos < len(text):
        start = text.find("{", pos)
        if start < 0:
            break
        try:
            obj, end = decoder.raw_decode(text, start)
        except ValueError as exc:
            if re.match(r'\s*["}]', text[start + 1:]):
                raise AnalysisError("Model returned incomplete or invalid JSON.") from exc
            # Braces in source-code reasoning are not JSON answer attempts.
            pos = start + 1
            continue
        objects.append(obj)
        pos = end
    if not objects or not isinstance(objects[-1], dict):
        raise AnalysisError("Model returned no complete JSON answer.")
    return objects[-1]


def check_boolean_field(text, field):
    """Validate and return a boolean answer without research-parser coercion."""
    obj = checked_object(text)
    if type(obj.get(field)) is not bool:
        raise AnalysisError("Model returned an invalid verdict schema.")
    return obj


def checked_items(text, field, key, value_type):
    obj = checked_object(text)
    items = obj.get(field)
    if not isinstance(items, list):
        raise AnalysisError("Model returned an invalid list schema.")
    values = []
    for item in items:
        value = item.get(key) if isinstance(item, dict) else item
        if type(value) is not value_type or (value_type is str and not value.strip()):
            raise AnalysisError("Model returned an invalid finding entry.")
        values.append(value.strip() if value_type is str else value)
    return values
