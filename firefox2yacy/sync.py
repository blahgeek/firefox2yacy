#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import datetime
import logging

from firefox2yacy import models
from firefox2yacy import firefox


logger = logging.getLogger(__name__)

_LAST_QUERIED_KEY = 'history.last_queried'
_QUERY_OVERLAP = 3600  # overlap 60min on each query
_BATCH_SIZE = 1000


def sync_histories(client: firefox.SyncClient, key: firefox.KeyBundle):
    last_queried = 0.0
    if last_queried_obj := models.State.get_or_none(key = _LAST_QUERIED_KEY):
        last_queried = float(last_queried_obj.value)

    offset = 0
    while True:
        content = client.get_records('history', sort='oldest', full=True,
                                     limit=_BATCH_SIZE,
                                     offset=offset,
                                     newer=max(last_queried - _QUERY_OVERLAP, 0.0))
        try:
            offset = int(client.raw_resp.headers['X-Weave-Next-Offset'])
        except:
            logger.warning('No X-Weave-Next-Offset, maybe EOS')
            offset += len(content)

        if not content:
            break

        logger.info(f'Got {len(content)} records newer than {last_queried}, next offset {offset}')

        rows = []
        for record in content:
            try:
                payload = firefox.decrypt_payload(record['payload'], key)
            except ValueError:
                logger.exception(f'Cannot parse record {record}')
                continue

            if payload.get('deleted'):
                continue

            visit_timestamps = [int(x['date']) / 1000000 for x in payload['visits']]
            rows.append({
                'id': payload['id'],
                'url': payload['histUri'],
                'title': payload['title'],
                'first_visit': datetime.datetime.fromtimestamp(min(visit_timestamps)),
                'last_visit': datetime.datetime.fromtimestamp(max(visit_timestamps)),
                'visit_count': len(visit_timestamps),
            })

        models.History.insert_many(rows).on_conflict_replace().execute()

    (models.State.insert(key = _LAST_QUERIED_KEY,
                         value = str(time.time()))
        .on_conflict_replace()
        .execute())

