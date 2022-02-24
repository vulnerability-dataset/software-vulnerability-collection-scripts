#!/usr/bin/env python3

"""
	This script converts the engine from any table using MyISAM to InnoDB.

	See: https://dev.mysql.com/doc/refman/8.0/en/converting-tables-to-innodb.html
"""

from modules.common import log, DATABASE_CONFIG
from modules.database import Database

####################################################################################################

with Database() as db:

	log.info('Converting tables from MyISAM to InnoDB.')

	database_name = DATABASE_CONFIG['database']
	success, error_code = db.execute_query(	'''
											SELECT TABLE_NAME, CONCAT('ALTER TABLE ', TABLE_NAME,' ENGINE=InnoDB;') AS QUERY
											FROM INFORMATION_SCHEMA.TABLES
											WHERE ENGINE='MyISAM'
											AND TABLE_SCHEMA = %(database_name)s
											ORDER BY TABLE_NAME;
											''',
											params={'database_name': database_name})

	if success:

		row_list = [row for row in db.cursor]
		log.info(f'Converting a total of {len(row_list)} tables.')

		for row in row_list:

			table = row['TABLE_NAME']
			query = row['QUERY']

			log.info(f'Converting the table "{table}" using the query "{query}".')

			success, error_code = db.execute_query(query)

			if not success:
				log.error(f'Failed to convert the table "{table}" with the error code {error_code}.')

	else:
		log.error(f'Failed to build the queries to convert the tables from MyISAM to InnoDB with the error code {error_code}.')

log.info('Finished running.')
print('Finished running.')
