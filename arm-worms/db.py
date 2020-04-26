#!/usr/bin/env python3

import datetime

from peewee import (DateTimeField, FloatField, ForeignKeyField, IntegerField,
                    Model, SqliteDatabase, TextField, UUIDField)

db_connection = SqliteDatabase('database.dat')


class BaseModel(Model):
    class Meta(type):
        database = db_connection


class Round(BaseModel):
    pass


class Replay(BaseModel):
    id = UUIDField(primary_key=True)
    json_replay = TextField()
    json_map = TextField()
    round = ForeignKeyField(Round)


class ReplayTest(BaseModel):
    id = UUIDField(primary_key=True)
    json_replay = TextField()
    json_map = TextField()


db_connection.create_tables([Round, Replay, ReplayTest], safe=True)

if __name__ == '__main__':
    pass
