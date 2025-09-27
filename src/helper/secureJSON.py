#!/bin/python

# Copyright © 2019-2025, KASTEL Security Research Labs, Maximilian Noppel, Christoph Niederbudde, Michael Kirsten


import json
import os


def loadSecureJSON(path, filename, sequence=True, plain=False):
    with open(os.path.join(path, filename), 'rb') as filestr:
        if plain:
            return json.loads(filestr.read())
        else:
            file = json.loads(filestr.read())
            jsonObjects = [entry for entry in file[0:len(file) - 1]]
            contentList = [json.loads(jsonObject["c"]) for jsonObject in jsonObjects]
            return [content["payload"] for content in contentList] if sequence else contentList[0]["payload"]
