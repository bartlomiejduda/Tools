"""
Copyright © 2026  Bartłomiej Duda
License: GPL-3.0 License
"""

import argparse
import sys
from pathlib import Path

from reversebox.common.logger import get_logger

logger = get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="WAD archive extraction and import tool")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--extract", action="store_true", help="Extract files from a WAD archive",)
    mode_group.add_argument("--import", dest="import_files", action="store_true", help="Import files into a WAD archive")

    parser.add_argument("input",type=Path, help="Input WAD archive (extract) or input directory (import)")
    parser.add_argument("output", type=Path, help="Output directory (extract) or output WAD archive (import)")

    args = parser.parse_args()

    if args.extract:
        wad_path = args.input
        output_directory = args.output

        if not wad_path.is_file():
            parser.error(f"WAD archive does not exist: {wad_path}")

        if not output_directory.exists():
            output_directory.mkdir(parents=True)

        # TODO: extract
        logger.info(f"Extracting '{wad_path}' to '{output_directory}'")

    elif args.import_files:
        input_directory = args.input
        wad_path = args.output

        if not input_directory.is_dir():
            parser.error(f"Input directory does not exist: {input_directory}")

        # TODO: import
        logger.info(f"Importing '{input_directory}' into '{wad_path}'")


if __name__ == "__main__":
    # TODO
    sys.argv = [
        "wad_tool.py",
        "--extract",
        "file.WAD",
        "output_directory",
    ]

    main()
