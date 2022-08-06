#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import logging

from firefox2yacy import models
from firefox2yacy import firefox


logger = logging.getLogger(__name__)

_NEXT_OFFSET_KEY = 'history.next_offset'
_BATCH_SIZE = 1000


def sync_histories(client: firefox.SyncClient, key: firefox.KeyBundle):
    while True:
        offset = 0
        if offset_obj := models.State.get_or_none(key = _NEXT_OFFSET_KEY):
            offset = int(offset_obj.value)

        content = client.get_records('history', sort='oldest', full=True,
                                     limit=_BATCH_SIZE, offset=offset)
        try:
            next_offset = int(client.raw_resp.headers['X-Weave-Next-Offset'])
        except:
            logger.warning('No X-Weave-Next-Offset, maybe EOS')
            next_offset = offset + len(content)

        if not content:
            break

        logger.info(f'Got {len(content)} records at {offset}, next offset {next_offset}')

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
        (models.State.insert(key = _NEXT_OFFSET_KEY,
                             value = str(next_offset))
         .on_conflict_replace()
         .execute())

