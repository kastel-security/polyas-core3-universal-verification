#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde


import json
import os


def loadSecureJSON(path, filename, plain = True):
    with open(os.path.join(path, filename)) as filestr:
        if plain:
            return json.loads(filestr.read())
        else:
            file = json.loads(filestr.read())
            jsonObjects = [entry for entry in file[0:len(file) - 1]]
            print(filename, len(file))
            print(filename, len(jsonObjects))
            contentList = [json.loads(jsonObject["c"]) for jsonObject in jsonObjects]
            board = [content["payload"] for content in contentList]
            if len(board) == 1:
                return board[0]
            else:
                return board

