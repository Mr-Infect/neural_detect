import sys

try:
    from ndctl.cli import main
except ModuleNotFoundError as exc:  # missing project libraries, usually the wrong Python
    sys.exit(
        f"ndctl cannot start: the Python library '{exc.name}' is not installed for {sys.executable}.\n"
        "ndctl needs Python 3.12+ and the project dependencies. Pick one:\n"
        "  1. No install: docker compose exec api python -m ndctl --help\n"
        "  2. Virtual environment:\n"
        "       uv venv --python 3.12 .venv && . .venv/bin/activate\n"
        "       uv pip install -r requirements.lock -e .\n"
        "       ndctl --help"
    )

sys.exit(main())
