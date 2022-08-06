#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import logging

from firefox2yacy import firefox
from firefox2yacy import sync
from firefox2yacy import models


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('--data-dir', default=os.path.expanduser('~/.firefox2yacy/'))
    args = parser.parse_args()

    data_dir = args.data_dir
    os.makedirs(data_dir, exist_ok=True)

    models.db.init(os.path.join(data_dir, 'db.sqlite3'), pragmas={'journal_mode': 'wal'})
    models.db.create_tables(models.MODELS)

    client, key = firefox.get_client_and_key(args.username, args.password,
                                             os.path.join(data_dir, f'{args.username}.pickle'))
    sync.sync_histories(client, key)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
