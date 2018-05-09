#!/usr/bin/python
# title            :mongo_drop.py
# author           :Alex
# description      :clean the database
# date             :01-01-2018
# ==============================================================================
from pymongo import MongoClient

if __name__ == "__main__":
    # client = MongoClient("mongodb://IRTLab:iotsecurity@ \
    #                     irtcluster-shard-00-00-j79ga.mongodb.net:27017, \
    #                     irtcluster-shard-00-01-j79ga.mongodb.net:27017, \
    #                     irtcluster-shard-00-02-j79ga.mongodb.net:27017/test? \
    #                     ssl=true&replicaSet=IRTCluster-shard-0&authSource=admin")
    client = MongoClient('localhost', 27017)
    client.drop_database('traffic-db')
