#!/usr/bin/env python3

"""
	This module defines a class that represents a MySQL database connection and that contains methods for querying its information.
"""

import os
import subprocess
import sys
from typing import Iterator, Optional, Tuple, Union

from mysql.connector import MySQLConnection, Error as MySQLError # type: ignore
from mysql.connector.cursor import MySQLCursor # type: ignore

from .common import log, GLOBAL_CONFIG, DATABASE_CONFIG

class Database:
	""" Represents a connection to the software vulnerability MySQL database. """

	host: str
	port: str
	user: str
	password: str
	database: str

	connection: MySQLConnection
	cursor: MySQLCursor

	input_directory_path: str

	def __init__(self, config: dict = DATABASE_CONFIG, **kwargs):

		try:
			log.info(f'Connecting to the database with the following configurations: {config}')
			
			for key, value in config.items():
				setattr(self, key, value)
			
			self.connection = MySQLConnection(**config)
			self.cursor = self.connection.cursor(dictionary=True, **kwargs)

			log.info(f'Autocommit is {self.connection.autocommit}.')

			self.input_directory_path = os.path.abspath(GLOBAL_CONFIG['output_directory_path'])

		except MySQLError as error:
			log.error(f'Failed to connect to the database with the error: {repr(error)}')
			sys.exit(1)

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):

		try:
			self.cursor.close()
			self.connection.close()
		except MySQLError as error:
			log.error(f'Failed to close the connection to the database with the error: {repr(error)}')

	def execute_query(self, query: str, commit: bool = False, **kwargs) -> Tuple[bool, Optional[int]]:
		""" Executes a given SQL query and optionally commits the results. """

		try:
			self.cursor.execute(query, **kwargs)
			if commit:
				self.connection.commit()
			
			success = True
			error_code = None
		
		except MySQLError as error:
			success = False
			error_code = error.errno
			log.warning(f'Failed to execute the query "{query}" with the error: {repr(error)}')

		return (success, error_code)

	def commit(self) -> bool:
		""" Commits the current transaction. """

		try:
			self.connection.commit()
			success = True
		except MySQLError as error:
			success = False
			log.error(f'Failed to perform the commit with the error: {repr(error)}')

		return success

	def rollback(self) -> bool:
		""" Rolls back the current transaction. """

		try:
			self.connection.rollback()
			success = True
		except MySQLError as error:
			success = False
			log.error(f'Failed to perform the rollback with the error: {repr(error)}')

		return success

	def execute_script(self, script_path: str) -> Tuple[bool, str]:
		""" Executes one or more SQL queries inside a file and returns the output of the MySQL command. """

		arguments = ['mysql',
					f'--host={self.host}', f'--port={self.port}', f'--user={self.user}', f'--password={self.password}',
					'--default-character-set=utf8', '--comments', self.database]
		
		try:
			script_file = open(script_path)
			result = subprocess.run(arguments, stdin=script_file, capture_output=True, text=True)
			success = result.returncode == 0
			output = result.stdout

			if not success:
				command_line_arguments = ' '.join(arguments)
				error_message = result.stderr or result.stdout
				log.error(f'Failed to run the command "{command_line_arguments}" with the error code {result.returncode} and the error message "{error_message}".')

		except Exception as error:
			success = False
			output = ''
			log.error(f'Failed to execute the script "{script_path}" with the error: {repr(error)}')

		return (success, output)

	def call_procedure(self, name: str, *args) -> Tuple[bool, tuple]:
		""" Calls a previously created stored procedure. """

		try:
			output = self.cursor.callproc(name, args)
			success = True
		except Exception as error:
			success = False
			output = ()
			log.error(f'Failed to call the procedure "{name}" with the error: {repr(error)}')

		return (success, output)