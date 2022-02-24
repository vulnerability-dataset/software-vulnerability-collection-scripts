#!/usr/bin/env python3

"""
	This script merges the FILES_*, FUNCTIONS_*, and CLASSES_* tables into a single one for each project and code unit.
"""

from modules.common import log, DATABASE_CONFIG
from modules.database import Database
from modules.project import Project

####################################################################################################

def merge_files_functions_classes_in_database() -> None:

	with Database() as db:

		database_name = DATABASE_CONFIG['database']
		project_list = Project.get_project_list_from_config()

		for project in project_list:

			for prefix in ['FILES_', 'FUNCTIONS_', 'CLASSES_']:

				table_target = prefix + str(project.database_id)
				log.info(f'Merging the "{table_target}" tables for the project "{project}".')

				success, error_code = db.execute_query(	'''
														SELECT TABLE_NAME
														FROM INFORMATION_SCHEMA.TABLES
														WHERE TABLE_NAME LIKE %(table_pattern)s
														AND TABLE_TYPE = 'BASE TABLE'
														AND TABLE_SCHEMA = %(database_name)s
														ORDER BY TABLE_NAME;
														''',
														params={'table_pattern': table_target + '%', 'database_name': database_name})

				if not success:
					log.error(f'Failed to retrieve the table names with the error code {error_code}.')
					return

				##################################################

				table_list = [row['TABLE_NAME'] for row in db.cursor]
				table_template = table_list[0]

				log.info(f'Merging a total of {len(table_list)} tables.')

				success, error_code = db.execute_query(f'''
														CREATE TABLE {table_target} LIKE {table_template};
														''')

				if not success:
					log.error(f'Failed to create the merged table "{table_target}" with the error code {error_code}.')
					return

				table_union = ' UNION ALL '.join([f'SELECT * FROM {table}' for table in table_list])

				##################################################

				success, error_code = db.execute_query(f'''
														INSERT INTO {table_target} SELECT * FROM ({table_union}) AS U;
														''')

				if not success:
					log.error(f'Failed to insert the merged data into "{table_target}" with the error code {error_code}.')
					return

		##################################################

		log.info('Committing changes.')
		db.commit()

merge_files_functions_classes_in_database()

log.info('Finished running.')
print('Finished running.')
