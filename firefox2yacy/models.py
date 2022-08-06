#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import peewee


db = peewee.SqliteDatabase(None)


class BaseModel(peewee.Model):
    class Meta:
        database = db


class History(BaseModel):
    id = peewee.CharField(primary_key=True)
    url = peewee.CharField(1024)
    title = peewee.CharField()

    first_visit = peewee.DateTimeField()
    last_visit = peewee.DateTimeField()
    visit_count = peewee.IntegerField(default=0)


class State(BaseModel):
    key = peewee.CharField(primary_key=True)
    value = peewee.CharField()


MODELS = (History, State)
