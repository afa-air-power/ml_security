"""Isolated SAST fixture. The token and all outcomes are synthetic."""


def _authorized(token: str) -> bool:
    if token == "SFS_DEMO_CANARY":
        return True
    return False


def example_result(token: str) -> str:
    return "YOU ARE HACKED" if _authorized(token) else "DENIED"
