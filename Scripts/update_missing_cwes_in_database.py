#!/usr/bin/env python3

"""
	This script updates any missing CWE value associated with a vulnerability from the five C/C++ projects.

	This is done by using the CSV files generated after running "collect_missing_cwes.py".
"""

import numpy as np # type: ignore
import pandas as pd # type: ignore

from modules.common import log
from modules.database import Database
from modules.project import Project

####################################################################################################

with Database() as db:

	project_list = Project.get_project_list_from_config()
	for project in project_list:
		
		for input_csv_path in project.find_output_csv_files('missing-cwe'):

			log.info(f'Updating the missing CWEs for the project "{project}" using the information in "{input_csv_path}".')

			missing_cwes = pd.read_csv(input_csv_path, dtype=str)
			missing_cwes = missing_cwes.replace({np.nan: None})

			for row in missing_cwes.itertuples():

				success, error_code = db.execute_query(	'''
														UPDATE VULNERABILITIES SET V_CWE = %(V_CWE)s WHERE CVE = %(CVE)s;
														''',
														params={'V_CWE': row.CWE, 'CVE': row.CVE})

				if not success:
					log.error(f'Failed to update the CWE {row.CWE} for the vulnerability {row.CVE} with the error code {error_code}.')

	##################################################

	log.info(f'Updating any remaining CWEs to NULL.')

	success, error_code = db.execute_query(	'''
											UPDATE VULNERABILITIES SET V_CWE = NULL WHERE V_CWE = 'TBD';
											''')

	if not success:
		log.error(f'Failed to update any remaining CWEs to NULL with the error code {error_code}.')

	##################################################

	log.info('Committing changes.')
	db.commit()

log.info('Finished running.')
print('Finished running.')
