#!/bin/zsh
set -e
cd -- "${0:A:h}"
if command -v uv >/dev/null 2>&1; then
    exec uv run --frozen sdes-lab
fi
if [[ ! -x .venv/bin/python ]]; then
    python3 -m venv .venv
    .venv/bin/python -m pip install -e .
fi
exec .venv/bin/python -m sdes
