"""Module logger setup.

The framework never calls `print()`; it logs through the standard `logging`
module under the `idanalysister` namespace so a host application (or IDA's
own output window, via a handler the user attaches) controls visibility.
A `NullHandler` is installed by default so importing the package is silent
until the user configures logging.
"""

from __future__ import annotations

import logging

_ROOT_NAME = "idanalysister"

logging.getLogger(_ROOT_NAME).addHandler(logging.NullHandler())


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger under the `idanalysister` namespace.

    `name` is a dotted suffix, e.g. `get_logger("core.engine_backward")`.
    """
    full_name = _ROOT_NAME if not name else f"{_ROOT_NAME}.{name}"
    return logging.getLogger(full_name)
