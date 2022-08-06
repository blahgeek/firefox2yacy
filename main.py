#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import logging

from firefox2yacy import firefox
from firefox2yacy import sync
from firefox2yacy import models
from firefox2yacy import yacy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--firefox-user', required=True)
    parser.add_argument('--firefox-pass', required=True)
    parser.add_argument('--yacy-user', default='admin')
    parser.add_argument('--yacy-pass', default='yacy')
    parser.add_argument('--yacy-host', required=True)
    parser.add_argument('--data-dir', default=os.path.expanduser('~/.firefox2yacy/'))
    args = parser.parse_args()

    data_dir = args.data_dir
    os.makedirs(data_dir, exist_ok=True)

    models.db.init(os.path.join(data_dir, 'db.sqlite3'), pragmas={'journal_mode': 'wal'})
    models.db.create_tables(models.MODELS)

    client, key = firefox.get_client_and_key(args.firefox_user, args.firefox_pass,
                                             os.path.join(data_dir, f'{args.firefox_user}.pickle'))
    sync.sync_histories(client, key)

    yacy_setting = yacy.YacySetting(host = args.yacy_host,
                                    username = args.yacy_user,
                                    password = args.yacy_pass)
    yacy.update_yacy_all(yacy_setting)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
