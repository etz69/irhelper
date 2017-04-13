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
        command = "CREATE TABLE IF NOT EXISTS %s (" %table_name
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

            cmd = 'INSERT INTO %s (%s) VALUES (%s);' % \
                  (table_name, ",".join(elem.keys()), ",".join(values))

            #debug(cmd)
            c = self.conn.cursor()
            c.execute(cmd)

        self.conn.commit()

    def add_column_ifnot_exists(self, table_name, column_name, column_type):
        '''
        Add a column to an exisitng table

        @table_name: the table name

        @column_name: the new column name

        @column_type: The type of the new column

        '''
        ##ALTER TABLE exiftool ADD COLUMN sentropy text;
        #rdb = DBOps("results.db")
        #command = "ALTER TABLE exiftool ADD COLUMN sentropy text"
        sql = 'ALTER TABLE '+table_name+' ADD COLUMN ' \
                                        ''+column_name+' '+column_type+''
        #rdb.conn.execute(command)
        try:
            c = self.conn.cursor()
            c.execute(sql)
        except Exception, e:
            debug("Column %s probable exists" %column_name)
            ##Assume it exists :/
            pass
        ##debug("Function [%s] not implemented" %__name__)


    def update_value(self, table_name, column_name, value, key_name, key):

        sql = 'UPDATE '+table_name+' set '+column_name+'='+value+'' \
                ' WHERE '+key_name+'="'+key+'"'
        c = self.conn.cursor()
        c.execute(sql)
        self.conn.commit()

##This has to changed to support field selections as well
    def get_all_rows(self, table_name):

        sql = 'SELECT * from '+table_name+''

        c = self.conn.cursor()
        c.row_factory = sqlite3.Row
        c.execute(sql)

        rows = c.fetchall()
        return rows