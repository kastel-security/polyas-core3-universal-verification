#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde


import json
import os


def loadSecureJSON(path, filename, sequence = True, plain = True):
    with open(os.path.join(path, filename)) as filestr:
        if plain:
            return json.loads(filestr.read())
        else:
            file = json.loads(filestr.read())
            jsonObjects = [entry for entry in file[0:len(file) - 1]]
            contentList = [json.loads(jsonObject["c"]) for jsonObject in jsonObjects]
            return [content["payload"] for content in contentList] if sequence else contentList[0]["payload"]

