#!/usr/bin/python
# title            :mongo_install.py
# author           :Alex
# description      :used for local database, installation database
# date             :01-01-2018
# ==============================================================================
from pymongo import MongoClient
import pprint

if __name__ == "__main__":
    client = MongoClient('localhost', 27017)
    db = client['traffic-db']
    flow_stats = db['flow_stats']
    session_stats = db['session_stats']
    one_way_stats = db['one_way_stats']
    devices = db['devices']
