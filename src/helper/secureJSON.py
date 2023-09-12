#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, CHristoph Niederbudde


import json
import os


def loadSecureJSON(path, filename):
    with open(os.path.join(path, filename)) as filestr:
        filejson = json.loads(filestr.read())
        return filejson
