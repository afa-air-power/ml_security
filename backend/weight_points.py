import math
import re

# Store matched rule names and coordinates, never the original text.
PROMPT_RULES = {
    "instruction_override": re.compile(rb"ignore (?:all |the )?(?:previous|prior) instructions", re.I),
    "system_override": re.compile(rb"(?:disregard|override) (?:the )?system (?:prompt|instructions)", re.I),
    "secret_request": re.compile(rb"(?:reveal|print|exfiltrate) (?:the )?(?:system prompt|api key|secrets)", re.I),
}
PROMPT_FIELDS = {"chat_template", "system_prompt", "prompt_template", "instructions"}


def coordinates(shape: list[int], index: int) -> list[int] | None:
    if not shape or not all(type(size) is int and size > 0 for size in shape):
        return None
    if index < 0 or index >= math.prod(shape):
        return None
    result = []
    for size in reversed(shape):
        index, offset = divmod(index, size)
        result.append(offset)
    return list(reversed(result))


def prompt_matches(data: bytes) -> list[tuple[str, int]]:
    return [
        (rule, match.start())
        for rule, pattern in PROMPT_RULES.items()
        if (match := pattern.search(data))
    ]
