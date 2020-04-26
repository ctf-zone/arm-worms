#!/usr/bin/env python3

import base64
import binascii
import json
import os
import subprocess
import tempfile
import time
from uuid import uuid4

import peewee
import requests
from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request)

from db import Replay, ReplayTest, Round
from settings import DEFAULT_SHELLCODE, TEAMS, VIS_HOST
from utils import dump

app = Flask(__name__)


@app.route('/test', methods=['GET', 'POST'])
def test():
    teams = [{'name': TEAMS[team_id]} for team_id in TEAMS]
    if request.method == 'GET':
        return render_template('test.html', data=teams)
    if request.method == 'POST':
        fname = 'shellcode'
        team_name = request.form.get('team_name')
        shellcode = None
        if request.files.get(fname):
            shellcode = request.files[fname].read()[:512]
        if not shellcode:
            print('[error]\tfile not selected')
            return render_template('test.html',
                                   data=teams,
                                   error='File not selected.')

        shellcodes = {TEAMS[team_id]: DEFAULT_SHELLCODE for team_id in TEAMS}
        shellcodes[team_name] = binascii.hexlify(bytearray(shellcode)).decode()
        print('[shellcodes]\t{}'.format(json.dumps(shellcodes, indent=4)))
        tmp = tempfile.NamedTemporaryFile(prefix='shellcode_',
                                          suffix='.json',
                                          delete=False)
        with open(tmp.name, 'w') as f:
            json.dump(shellcodes, f)
        os.system(' '.join(['./core.py', 'play-game', tmp.name]))
        replay_file = tmp.name.replace('shellcode', 'replay')
        map_file = tmp.name.replace('shellcode', 'map')
        score_file = tmp.name.replace('shellcode', 'score')
        while not (os.path.isfile(replay_file) and os.path.isfile(map_file)
                   and os.path.isfile(score_file)):
            time.sleep(1)
        # yapf: disable
        print('[info]\tmap file: {}\n\treplay file: {}\n\tscore file {}'.format(
                map_file, replay_file, score_file))
        # get map
        with open(map_file, 'r') as f:
            map_json = json.load(f)
        # get replay
        with open(replay_file, 'r') as f:
            replay_json = json.load(f)
        # get score
        with open(score_file, 'r') as f:
            score_json = json.load(f)

        rnd = Round()
        rnd.save()

        d = Replay(id=uuid4(),
                   json_replay=json.dumps(replay_json),
                   json_map=json.dumps(map_json),
                   round=rnd)
        d.save(force_insert=True)

        return render_template('test.html', data=teams, _id=d.id)


@app.route('/test_all', methods=['GET', 'POST'])
def test_all():
    if request.method == 'GET':
        return render_template('test_all.html')
    if request.method == 'POST':
        shellcodes = {TEAMS[team_id]: DEFAULT_SHELLCODE for team_id in TEAMS}
        for i in range(10):
            fname = 'shellcode{:#d}'.format(i)
            shellcode = None
            if request.files.get(fname):
                shellcode = request.files[fname].read()[:512]
            if not shellcode:
                print('[error]\tfile not selected')
                return render_template('test_all.html',
                                       error='File not selected.')
            shellcodes[TEAMS[str(i + 1)]] = binascii.hexlify(
                bytearray(shellcode)).decode()
        print('[shellcodes]\t{}'.format(json.dumps(shellcodes, indent=4)))
        tmp = tempfile.NamedTemporaryFile(prefix='shellcode_',
                                          suffix='.json',
                                          delete=False)
        with open(tmp.name, 'w') as f:
            json.dump(shellcodes, f)
        os.system(' '.join(['./core.py', 'play-game', tmp.name]))
        replay_file = tmp.name.replace('shellcode', 'replay')
        map_file = tmp.name.replace('shellcode', 'map')
        score_file = tmp.name.replace('shellcode', 'score')
        while not (os.path.isfile(replay_file) and os.path.isfile(map_file)
                   and os.path.isfile(score_file)):
            time.sleep(1)
        print('[info]\tmap file: {}\n\treplay file: {}\n\tscore file {}'.format(
                map_file, replay_file, score_file))
        # get map
        with open(map_file, 'r') as f:
            map_json = json.load(f)
        # get replay
        with open(replay_file, 'r') as f:
            replay_json = json.load(f)
        # get score
        with open(score_file, 'r') as f:
            score_json = json.load(f)

        rnd = Round()
        rnd.save()

        d = Replay(id=uuid4(),
                   json_replay=json.dumps(replay_json),
                   json_map=json.dumps(map_json),
                   round=rnd)

        d.save(force_insert=True)

        return render_template('test_all.html', _id=d.id)


@app.route('/get_last_uuid')
def get_last_uuid():
    round = Replay.select().order_by(Replay.round_id.desc())
    if round.count():
        return str(round.get().id)
    else:
        return str('No')


@app.route('/json_replay/<_id>')
def json_replay(_id):
    query = Replay.select().where(Replay.id == _id)
    if query.count():
        return query.get().json_replay
    else:
        abort(404, 'No replay')


@app.route('/json_map/<_id>')
def json_map(_id):
    query = Replay.select().where(Replay.id == _id)
    if query.count():
        return query.get().json_map
    else:
        abort(404, 'No replay')


@app.route('/vis/<_id>')
def vis(_id):
    return redirect('http://{}/index.html?uuid={}'.format(VIS_HOST, _id),
                    code=302)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
