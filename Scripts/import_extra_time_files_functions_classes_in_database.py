#!/usr/bin/env python3

"""
	This script imports the EXTRA_TIME_FILES, *_FUNCTIONS, and *_CLASSES tables into the database. This is done by using the SQL scripts present in
	the dataset's directory. Note that this process takes a long time to complete.
"""

import glob
import os

from modules.common import log, GLOBAL_CONFIG
from modules.database import Database
from modules.project import Project

####################################################################################################

with Database() as db:

	project_name_list = [project.database_name for project in Project.get_project_list_from_config()]

	script_pattern = os.path.join(GLOBAL_CONFIG['dataset_path'], '**', r'EXTRA-TIME-*.sql')
	tables_to_import = [name.upper() for name in GLOBAL_CONFIG['extra_time_tables_to_import']]

	for script_path in glob.iglob(script_pattern, recursive=True):

		directory_name = os.path.basename(os.path.dirname(script_path))
		script_name = os.path.basename(script_path).upper()

		# Skip other projects like Derby and Tomcat, and only import data for the EXTRA_TIME tables we want.
		if directory_name in project_name_list and any(name in script_name for name in tables_to_import):

			success, output = db.execute_script(script_path)

			if success:
				log.info(f'Imported the data from "{script_path}" successfully.')
			else:
				log.error(f'Failed to import the data from "{script_path}": {output}')

print('Finished running.')
