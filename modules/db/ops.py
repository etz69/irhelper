#
# This file contains some ideas from DAMM but heavily modified
#
import sqlite3
import sys
import os
from modules.utils.helper import *


class DBOps:

    def __init__(self, db):
        self.conn = sqlite3.connect(db)

    def clean_db(self, db):
        '''
        Deletes the sqlite file (cleans the db)

        @db: Target db name (file)

        '''

        debug("Cleaning DB file")
        os.remove(db) if os.path.exists(db) else None
        self.conn=sqlite3.connect(db)


    def new_table(self, table_name, table_fields):
        '''
        Create a new db table

        @table_name: the table name

        @table_fields: Table fields is a dict containing the name of the
        column as the key and the data type as the value
        {'id':'integer','name':'text','path':'text'}
        '''
        command = "create table if not exists %s (" %table_name
        for key in table_fields:
            command += "%s %s," %(key,table_fields[key])

        command = command.rstrip(",") + ")"
        debug(command)
        self.conn.execute(command)

    def new_table_from_keys(self, table_name, table_keys):
        '''
        Create a new db table based on table keys with default type text

        @table_name: the table name

        @table_fields: Table fields is a dict containing the name of the
        column as the key and the data type as the value
        {'id':'integer','name':'text','path':'text'}
        '''
        command = "create table if not exists %s (" %table_name
        for key in table_keys:
            command += "%s %s," %(key,"text")

        command = command.rstrip(",") + ")"
        debug(command)
        self.conn.execute(command)

    def insert_into_table(self, table_name, row):
        '''
        Insert data into a table

        @table_name: the table name

        @data: Data is an array containing list of dictionary items in the form
        of columnName:value
        '''

        for elem in row:

            values = list([u'"{}"'.format(x) for x in elem.values()])

            cmd = 'insert into %s (%s) values (%s);' % \
                  (table_name, ",".join(elem.keys()), ",".join(values))

            #debug(cmd)
            c = self.conn.cursor()
            c.execute(cmd)

        self.conn.commit()
