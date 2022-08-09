#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import typing
import logging
import datetime
import dataclasses
import concurrent.futures
from peewee import threading
import requests
import requests.auth
import bs4

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
        'indexMedia': 'on',
        'deleteold': 'off',
        'crawlingQ': 'on',
        'recrawl': 'reload',
        'reloadIfOlderNumber': '0',
        'reloadIfOlderUnit': 'hour',
        'crawlerAlwaysCheckMediaType': 'on',
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
    if resp.status_code == 431:
        logger.debug('URL too large, ignore')
    else:
        resp.raise_for_status()

    item.last_submit = datetime.datetime.now()
    item.save()

    counter.finish_one()


def update_yacy_all(setting: YacySetting):
    query = (models.History.select()
             .where(models.History.last_submit.is_null(True) |
                    ((models.History.last_submit < models.History.last_visit) &
                     (models.History.last_submit < datetime.datetime.now() - datetime.timedelta(days=1)))))

    logger.info(f'Submitting {len(query)} URLs for yacy...')
    counter = _ProgressCounter(len(query))
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for item in query:
            executor.submit(submit_one, item, setting, counter)


# Keeping too much API history in /Table_API_p.html would make yacy consume a lot of CPU every few seconds
def clear_api_history(setting: YacySetting):
    page_resp = requests.get(f'{setting.host}/Table_API_p.html',
                             auth=requests.auth.HTTPDigestAuth(setting.username, setting.password))
    soup = bs4.BeautifulSoup(page_resp.content, features='html.parser')

    form = typing.cast(bs4.Tag, soup.find('form', {'action': 'Table_API_p.html'}))
    assert form is not None, 'Cannot find Table_API_p.html form'

    form_data = {}
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get('type')
        input_name = input_tag.attrs.get('name')
        input_value = input_tag.attrs.get('value')
        if not input_type or not input_name or not input_value:
            continue
        if (input_type == 'hidden' or input_type == 'text' or
            (input_type == 'submit' and input_name == 'deleteold')):
            form_data[input_name] = input_value
    form_data['deleteoldtime'] = '0'

    resp = requests.post(f'{setting.host}/Table_API_p.html',
                         auth=requests.auth.HTTPDigestAuth(setting.username, setting.password),
                         data=form_data)
    resp.raise_for_status()

