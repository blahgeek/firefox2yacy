#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import datetime
import dataclasses
import concurrent.futures
from peewee import threading
import requests
import requests.auth

from firefox2yacy import models


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class YacySetting:
    host: str
    username: str
    password: str

    # https://wiki.yacy.net/index.php/Dev:APICrawler
    crawler_options: dict[str, str] = dataclasses.field(default_factory=lambda: {
        'crawlingDepth': '0',
        'indexText': 'on',
        'crawlingQ': 'on',
        'recrawl': 'reload',
    })


class _ProgressCounter:

    _PROGRESS_EVERY_N = 100

    def __init__(self, total: int):
        self._pending = total
        self._lock = threading.Lock()

    def finish_one(self):
        with self._lock:
            self._pending -= 1
            val = self._pending
        if val % self._PROGRESS_EVERY_N == 0:
            logger.info(f'Remaining jobs: {val}')


def submit_one(item: models.History, setting: YacySetting, counter: _ProgressCounter):
    resp = requests.get(f'{setting.host}/Crawler_p.html',
                        auth=requests.auth.HTTPDigestAuth(setting.username, setting.password),
                        params=dict(crawlingstart='',
                                    crawlingMode='url',
                                    crawlingURL=str(item.url),
                                    **setting.crawler_options))
    resp.raise_for_status()

    item.last_submit = datetime.datetime.now()
    item.save()

    counter.finish_one()


def update_yacy_all(setting: YacySetting):
    query = (models.History.select()
             .where(models.History.last_submit.is_null(True) |
                    (models.History.last_submit < models.History.last_visit)))

    logger.info(f'Submitting {len(query)} URLs for yacy...')
    counter = _ProgressCounter(len(query))
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for item in query:
            executor.submit(submit_one, item, setting, counter)
