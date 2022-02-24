#!/usr/bin/env python3

"""
	This script adds two columns (BeginLine and EndLine) to the FUNCTIONS_* and CLASSES_* tables in the database.

	Before running this script, the code unit tables must be merged using "merge_files_functions_classes_in_database.py".
"""

from mysql.connector.errorcode import ER_DUP_FIELDNAME # type: ignore

from modules.common import log
from modules.database import Database
from modules.project import Project

####################################################################################################

def alter_functions_and_classes_in_database() -> None:

	with Database() as db:

		project_list = Project.get_project_list_from_config()
		for project in project_list:

			for table_prefix in ['FUNCTIONS_', 'CLASSES_']:

				table_name = table_prefix + str(project.database_id)

				log.info(f'Adding the BeginLine and EndLine columns to the {table_name} table.')
				
				##################################################

				success, error_code = db.execute_query(f'''
														ALTER TABLE {table_name}
														ADD COLUMN EndLine INTEGER AFTER Complement,
														ADD COLUMN BeginLine INTEGER AFTER Complement;
														''')

				if not success and error_code != ER_DUP_FIELDNAME:
					log.error(f'Failed to add the BeginLine and EndLine columns with the error code {error_code}.')
					return

		##################################################

		log.info('Committing changes.')
		db.commit()

alter_functions_and_classes_in_database()

log.info('Finished running.')
print('Finished running.')
