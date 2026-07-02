from __future__ import annotations

import sys
from pathlib import Path

from utils import Config, IntegrationError
from workflow import run


def main() -> int:
    try:
        config = Config.load(Path(__file__).with_name(".env"))
        run(config)
    except IntegrationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
