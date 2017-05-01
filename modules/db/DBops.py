import sqlite3
import sys
import os



class DBOps():

    def __init__(self, db):
        self.conn = sqlite3.connect(db)

    def clean_db(self, db):
        '''
        Deletes the sqlite file (cleans the db)

        @db: Target db name (file)

        '''

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

            c = self.conn.cursor()
            c.execute(cmd)

        self.conn.commit()

    def patch_table(self, table_name, column_name, column_type):
        '''
        Add a column to an exisitng table

        @table_name: the table name

        @column_name: the new column name

        @column_type: The type of the new column

        '''
        sql = 'ALTER TABLE '+table_name+' ADD COLUMN ' \
                                        ''+column_name+' '+column_type+''
        try:
            c = self.conn.cursor()
            c.execute(sql)
        except Exception as e:
            pass


    def table_exists(self, table_name):
        '''
        Check if a table exists

        @table_name: the table name

        '''
        flag = False
        sql = 'SELECT name FROM sqlite_master WHERE type =\"table\" ' \
                                        'AND name="'+table_name+'"'

        c = self.conn.cursor()
        c.execute(sql)
        rows = c.fetchall()

        if len(rows) > 0:
            flag = True

        return flag

    def update_value(self, table_name, column_name, value, key_name, key):
        '''
        Update a value in a table

        @table_name: The table name

        @column_name: The column name

        @value: The new value

        @key_name: The key name you want to filter on

        @key: The key value you want to filter on

        '''


        sql = 'UPDATE '+table_name+' set '+column_name+'="'+value+'"' \
                ' WHERE '+key_name+'="'+key+'"'
        c = self.conn.cursor()
        c.execute(sql)
        self.conn.commit()

    ##This has to changed to support field selections as well
    def get_all_rows(self, table_name):
        '''
        Retrieve all rows from a table

        @table_name: the table name

        '''

        sql = 'SELECT * from '+table_name+''

        c = self.conn.cursor()
        c.row_factory = sqlite3.Row
        c.execute(sql)

        rows = c.fetchall()
        return rows

    def sqlite_query_to_json(self, query):
        '''
        Execute a query and return all results in json format

        @query (str): A string which describes the query for sqlite.
        Complex queries with filters do not work always

        '''

        sql = query
        c = self.conn.cursor()
        c.row_factory = sqlite3.Row

        c.execute(sql)

        rows = c.fetchall()
        results = []

        for rs in rows:
            jdata = {}
            for key in rs.keys():
                jdata[key] = rs[key]
            results.append(jdata.copy())

        return results


