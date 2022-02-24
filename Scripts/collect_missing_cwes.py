#!/usr/bin/env python3

"""
	This script collects any missing CWE values associated with the five C/C++ projects by scraping the CVE Details website.

	For each project, this information is saved to a CSV file.
"""

import pandas as pd # type: ignore

from modules.common import log
from modules.cve import Cve
from modules.database import Database
from modules.project import Project

####################################################################################################

with Database() as db:

	project_list = Project.get_project_list_from_config()
	for project in project_list:
		
		query_success, error_code = db.execute_query(	'''
														SELECT DISTINCT CVE FROM VULNERABILITIES WHERE R_ID = %(R_ID)s AND V_CWE = 'TBD' ORDER BY CVE;
														''',
														params={'R_ID': project.database_id})

		if query_success:
			
			missing_cwes = pd.DataFrame(columns=['CVE', 'CWE'])

			for db_row in db.cursor:

				cve = db_row['CVE']
				csv_row = {'CVE': cve, 'CWE': None}

				if cve is not None:

					cve_object = Cve(cve, project)
					download_success = cve_object.download_cve_details_page()

					if download_success:
						cve_object.scrape_basic_attributes_from_page()
						csv_row['CWE'] = cve_object.cwe

						if cve_object.cwe is not None:
							log.info(f'Found the CWE {cve_object.cwe} associated with {cve} for the project "{project}".')
						else:
							log.info(f'Could not find a CWE associated with {cve} for the project "{project}".')
					else:
						log.error(f'Failed to download the page for {cve} for the project "{project}".')

				else:
					log.info(f'Skipping the page download for the NULL CVE for the project "{project}".')

				missing_cwes = missing_cwes.append(csv_row, ignore_index=True)
		
			output_csv_path = project.get_base_output_csv_path('missing-cwe')
			missing_cwes.to_csv(output_csv_path, index=False)

			log.info(f'Finished running for the project "{project}". The missing CWEs were saved to: {output_csv_path}')
		else:
			log.error(f'Failed to query the CVEs without a CWE value for the project "{project}" with the error code {error_code}.')

	##################################################

log.info('Finished running.')
print('Finished running.')
