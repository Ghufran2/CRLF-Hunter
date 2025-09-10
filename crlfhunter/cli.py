"""
Console script entry point for the CRLF Hunter package.

This module provides a ``main`` function that is registered in
``setup.py`` under ``console_scripts``. When installed via pip, a
``crlfhunter`` command will be available on the user's PATH which
delegates execution to this function. The wrapper adjusts ``sys.argv``
so that the underlying ``program_main`` in ``crlfhunter.core`` can
parse command-line arguments as if it were run as a script.
"""
from __future__ import annotations

import runpy
import sys
from typing import List


def main(argv: List[str] | None = None) -> None:
    """Entrypoint for the ``crlfhunter`` console script.

    Parameters
    ----------
    argv: list[str] | None
        Optional list of command-line arguments. If provided, it will
        replace ``sys.argv[1:]`` for argument parsing. When ``None``
        (the default), the current command-line arguments are used.
    """
    # Emulate being called as ``python -m crlfhunter.core`` by setting sys.argv
    sys.argv = ["crlfhunter"] + (argv if argv is not None else sys.argv[1:])
    # Execute the core module as a script; this will call program_main()
    runpy.run_module("crlfhunter.core", run_name="__main__")


if __name__ == "__main__":  # pragma: no cover
    main()