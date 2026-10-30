"""Allow ``python -m reuseguard`` to behave like the ``reuseguard`` command."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
