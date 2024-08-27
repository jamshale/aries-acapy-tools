"""Askar wallet tools."""

import argparse
import asyncio
import logging
import sys
from typing import Optional
from urllib.parse import urlparse

from .exporter import Exporter
from .multi_wallet_converter import MultiWalletConverter
from .pg_connection import PgConnection
from .sqlite_connection import SqliteConnection


def config():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser("askar-wallet-tools")
    parser.add_argument(
        "--strategy",
        required=True,
        choices=["export", "mt-convert-to-mw"],
        help=(
            "Specify migration strategy depending on database type, wallet "
            "management mode, and agent type."
        ),
    )
    parser.add_argument(
        "--uri",
        required=True,
        help=("Specify URI of database to be migrated."),
    )
    parser.add_argument(
        "--wallet-name",
        type=str,
        help=(
            "Specify name of wallet to be migrated for DatabasePerWallet "
            "(export) migration strategy."
        ),
    )
    parser.add_argument(
        "--wallet-key",
        type=str,
        help=(
            "Specify key corresponding to the given name of the wallet to "
            "be migrated for database per wallet (export) migration strategy."
        ),
    )
    parser.add_argument(
        "--multitenant-sub-wallet-name",
        type=str,
        help=(
            "The existing wallet name for a multitenant single wallet conversion."
            "The default if not provided is 'multitenant_sub_wallet'"
        ),
        default="multitenant_sub_wallet",
    )
    args, _ = parser.parse_known_args(sys.argv[1:])

    if args.strategy == "export":
        if not args.wallet_name:
            raise ValueError("Wallet name required for export strategy")
        if not args.wallet_key:
            raise ValueError("Wallet key required for export strategy")

    return args


async def main(
    strategy: str,
    uri: str,
    wallet_name: Optional[str] = None,
    wallet_key: Optional[str] = None,
    multitenant_sub_wallet_name: Optional[str] = "multitenant_sub_wallet",
):
    """Run the main function."""
    logging.basicConfig(level=logging.WARN)
    parsed = urlparse(uri)

    # Connection setup
    if parsed.scheme == "sqlite":
        conn = SqliteConnection(uri)
    elif parsed.scheme == "postgres":
        conn = PgConnection(uri)
    else:
        raise ValueError("Unexpected DB URI scheme")

    # Strategy setup
    if strategy == "export":
        await conn.connect()
        print("wallet_name", wallet_name)
        method = Exporter(conn=conn, wallet_name=wallet_name, wallet_key=wallet_key)
    elif strategy == "mt-convert-to-mw":
        await conn.connect()
        method = MultiWalletConverter(
            conn=conn,
            wallet_name=wallet_name,
            wallet_key=wallet_key,
            sub_wallet_name=multitenant_sub_wallet_name,
        )
    else:
        raise Exception("Invalid strategy")

    await method.run()


def entrypoint():
    """Entrypoint for the CLI."""
    args = config()
    asyncio.run(main(**vars(args)))


if __name__ == "__main__":
    asyncio.run(entrypoint())
