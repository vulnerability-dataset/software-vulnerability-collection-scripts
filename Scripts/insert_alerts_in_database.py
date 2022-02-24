#!/usr/bin/env python3

"""
	This script inserts the alert data from any CSV files present in the directory specified in the 'data_repository_path'
	configuration into the RULE, CWE_INFO, RULE_CWE_INFO, ALERT, ALERT_FUNCTION, and ALERT_CLASS tables in the database.

	Before running this script, the follow scripts must be first run:
	- "insert_metrics_in_database.py" to insert the previously collected code unit metrics into the database;
	- "create_alert_and_cwe_tables_in_database.py" to create the tables mentioned above;
	- "create_indexes_in_database.py" to add indexes that will speed up the alert insertion.
"""

import glob
import os
from itertools import chain, zip_longest
from tempfile import TemporaryDirectory
from typing import cast, Optional, Tuple
from zipfile import ZipFile

import numpy as np # type: ignore
import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, delete_file, extract_numeric
from modules.database import Database
from modules.project import Project
from modules.sats import Sat, CppcheckSat, FlawfinderSat

####################################################################################################

def insert_alerts_in_database() -> None:

	with Database(buffered=True) as db:

		success, error_code = db.execute_query('SELECT SAT_NAME, SAT_ID FROM SAT;')

		if not success:
			log.error(f'Failed to query the SAT IDs with the error code {error_code}.')
			return

		sat_id_from_name = {row['SAT_NAME']: row['SAT_ID'] for row in db.cursor}
		log.info(f'Found the following SATs: {sat_id_from_name}')

		project_list = Project.get_project_list_from_config()
		for project in project_list:

			cppcheck = CppcheckSat(project)
			flawfinder = FlawfinderSat(project)

			file_metrics_table = 'FILES_' + str(project.database_id)
			function_metrics_table = 'FUNCTIONS_' + str(project.database_id)
			class_metrics_table = 'CLASSES_' + str(project.database_id)

			SELECT_FILE_ID_QUERY = f'''
									SELECT F.ID_File FROM {file_metrics_table} AS F
									INNER JOIN EXTRA_TIME_FILES AS E ON F.ID_File = E.ID_File
									INNER JOIN PATCHES AS P ON E.P_ID = P.P_ID
									WHERE P.R_ID = %(R_ID)s AND P.P_COMMIT = %(P_COMMIT)s
									AND F.FilePath = %(FILE_PATH)s AND F.Occurrence = %(P_OCCURRENCE)s;
									'''

			with TemporaryDirectory() as temporary_directory_path:

				sat_list = Sat.get_sat_info_from_config()
				for sat in sat_list:

					sat_id = sat_id_from_name.get(sat.database_name)

					if sat_id is None:
						log.error(f'The SAT "{sat}" does not exist in the database.')
						continue

					cached_rule_ids: dict = {}

					def find_zipped_csv_files(commit_type: str) -> list:
						""" Finds the paths to any zipped CSV files that belong to this project, SAT and commit type (current or previous). """

						# E.g. "mozilla/cppcheck/complete_scan/current_commit/part1/cppcheck-195-305babb41123e575e6fd6bf4ea4dab2716ce1ecc.csv.zip"
						# E.g. "linux/flawfinder/complete_scan/previous_commit/part4/flawfinder-358-fc1ca73b3758f0c419b46cfeb2a951de22007d90-1.csv.zip"
						base_directory = f'{project.github_data_name}/{sat.github_data_name}/complete_scan/{commit_type}'
						
						data_path = os.path.join(GLOBAL_CONFIG['data_repository_path'], base_directory, '**', '*.csv.zip')
						data_path = os.path.normpath(data_path)

						data_file_list = glob.glob(data_path, recursive=True)
						data_file_list = list(filter(os.path.isfile, data_file_list))
						data_file_list = sorted(data_file_list, reverse=True)

						return data_file_list

					neutral_file_list = find_zipped_csv_files('current_commit')
					vulnerable_file_list = find_zipped_csv_files('previous_commit')

					# Create a list of alternating zipped CSV paths, regardless of each list's length.
					zip_file_list: list = list(filter(None, chain.from_iterable(zip_longest(neutral_file_list, vulnerable_file_list))))

					log.info(f'Starting the insertion of {len(zip_file_list)} CSV alert files.')

					for i, zip_file_path in enumerate(zip_file_list):

						zip_filename = os.path.basename(zip_file_path)

						# E.g. "cppcheck-195-305babb41123e575e6fd6bf4ea4dab2716ce1ecc.csv.zip"
						# E.g. "flawfinder-358-fc1ca73b3758f0c419b46cfeb2a951de22007d90-1.csv.zip"
						# Note the "-1" in the previous_commit. This means we are in "previous_commit" and the real commit hash
						# is the one immediately before the one shown here.
						_, _, commit_hash = zip_filename.split('-', 2)
						commit_hash, _, _ = commit_hash.rsplit('.', 2)

						occurrence = 'before' if commit_hash.endswith('-1') else 'after'
						commit_hash = commit_hash.rstrip('-1')

						success, error_code = db.execute_query(	'''
																SELECT
																	(SELECT COUNT(*) > 0 FROM PATCHES WHERE R_ID = %(R_ID)s AND P_COMMIT = %(P_COMMIT)s) AS PATCH_EXISTS,
																	(
																		SELECT COUNT(*) > 0 FROM ALERT AS A
																		INNER JOIN RULE AS R ON A.RULE_ID = R.RULE_ID
																		WHERE R.SAT_ID = %(SAT_ID)s AND A.R_ID = %(R_ID)s
																		AND A.P_COMMIT = %(P_COMMIT)s AND A.P_OCCURRENCE = %(P_OCCURRENCE)s
																	) AS SAT_ALERTS_ALREADY_EXIST_FOR_THIS_COMMIT
																;
																''',
																params={'SAT_ID': sat_id, 'R_ID': project.database_id,
																		'P_COMMIT': commit_hash, 'P_OCCURRENCE': occurrence})

						if not success:
							log.error(f'Failed to query any existing patches with the commit {commit_hash} ({occurrence}, "{zip_filename}") in the project "{project}" with the error code {error_code}.')
							continue

						alert_row = db.cursor.fetchone()
						
						if alert_row['PATCH_EXISTS'] == 0:
							log.warning(f'Skipping the patch with the commit {commit_hash} ({occurrence}, "{zip_filename}") in the project "{project}" since it does not exist in the database.')
							continue

						if alert_row['SAT_ALERTS_ALREADY_EXIST_FOR_THIS_COMMIT'] == 1:
							log.info(f'Skipping the alerts for the commit {commit_hash} ({occurrence}, "{zip_filename}") in the project "{project}" since they already exist.')
							continue

						log.info(f'Inserting the alerts {i+1} of {len(zip_file_list)} from "{zip_file_path}" ({occurrence}).')

						with ZipFile(zip_file_path, 'r') as zip_file: # type: ignore[assignment]
							filenames_in_zip = zip_file.namelist() # type: ignore[attr-defined]
							zip_file.extractall(temporary_directory_path) # type: ignore[attr-defined]

						csv_file_path = os.path.join(temporary_directory_path, filenames_in_zip[0])

						cached_file_ids: dict = {}

						##################################################

						def insert_rule_and_cwe_info(alert_params: dict, cwe_list: list) -> Tuple[bool, Optional[int]]:
							""" Inserts a security alert's rule and CWEs in the database. This function is successful and returns the rule's primary
							key if a new row was inserted or if the rule already exists. """

							total_success = True
							rule_id = None

							alert_params['SAT_ID'] = sat_id

							success, error_code = db.execute_query(	'''
																	INSERT IGNORE INTO RULE (RULE_NAME, RULE_CATEGORY, SAT_ID)
																	VALUES (%(RULE_NAME)s, %(RULE_CATEGORY)s, %(SAT_ID)s);
																	''', params=alert_params)

							if not success:
								total_success = False
								log.error(f'Failed to insert the rule with the error code {error_code} and the parameters: {alert_params}.')

							for cwe in cwe_list:

								success, error_code = db.execute_query('INSERT IGNORE INTO CWE_INFO (V_CWE) VALUES (%(V_CWE)s);', params={'V_CWE': cwe})
								if not success:
									total_success = False
									log.error(f'Failed to insert the info for the CWE {cwe} with the error code {error_code} and the parameters: {alert_params}.')

							rule_key = (sat_id, alert_params['RULE_NAME'])
							rule_id = cached_rule_ids.get(rule_key, -1)
							if rule_id == -1:
							
								success, error_code = db.execute_query(	'SELECT RULE_ID FROM RULE WHERE RULE_NAME = %(RULE_NAME)s AND SAT_ID = %(SAT_ID)s;',
																		params=alert_params)

								if success and db.cursor.rowcount > 0:
									rule_row = db.cursor.fetchone()
									rule_id = rule_row['RULE_ID']
								else:
									rule_id = None
									total_success = False
									log.error(f'Failed to query the rule ID for {rule_key} wiwith the error code {error_code} and the parameters: {alert_params}.')

								cached_rule_ids[rule_key] = rule_id

							if rule_id is None:
								total_success = False
							else:
								for cwe in cwe_list:

									success, error_code = db.execute_query(	'''
																			INSERT IGNORE INTO RULE_CWE_INFO (RULE_ID, V_CWE)
																			VALUES
																			(
																				%(RULE_ID)s,
																				%(V_CWE)s
																			);
																			''', params={'RULE_ID': rule_id, 'V_CWE': cwe})

									if not success:
										total_success = False
										log.error(f'Failed to insert the key ({rule_id}, {cwe}) in RULE_CWE_INFO with the error code {error_code} and the parameters: {alert_params}.')

							return total_success, rule_id

						def insert_alert(alert_params: dict, cwe_list: list) -> None:
							""" Inserts a security alert in the database given its parameters: RULE_NAME, RULE_CATEGORY, ALERT_SEVERITY_LEVEL,
							ALERT_LINE, ALERT_MESSAGE, FILE_PATH, and a list of CWEs. """

							alert_params['R_ID'] = project.database_id
							alert_params['P_COMMIT'] = commit_hash
							alert_params['P_OCCURRENCE'] = occurrence

							success, rule_id = insert_rule_and_cwe_info(alert_params, cwe_list)

							if success:
								alert_params['RULE_ID'] = rule_id

								file_path = alert_params['FILE_PATH']
								file_id = cached_file_ids.get(file_path, -1)
								if file_id == -1:

									success, error_code = db.execute_query(SELECT_FILE_ID_QUERY, params=alert_params)

									if success and db.cursor.rowcount > 0:
										file_id_row = db.cursor.fetchone()
										file_id = file_id_row['ID_File']
									else:
										file_id = None

									cached_file_ids[file_path] = file_id

								if file_id is not None:
									
									alert_params['ID_File'] = file_id

									success, error_code = db.execute_query(	'''
																			INSERT INTO ALERT
																			(
																				ALERT_SEVERITY_LEVEL, ALERT_LINE, ALERT_MESSAGE,
																				R_ID, P_COMMIT, P_OCCURRENCE,
																				RULE_ID, ID_File
																			)
																			VALUES
																			(
																				%(ALERT_SEVERITY_LEVEL)s, %(ALERT_LINE)s, %(ALERT_MESSAGE)s,
																				%(R_ID)s, %(P_COMMIT)s, %(P_OCCURRENCE)s,
																				%(RULE_ID)s, %(ID_File)s
																			);
																			''', params=alert_params)

									if success:

										alert_params['ALERT_ID'] = db.cursor.lastrowid

										success, error_code = db.execute_query(f'''
																				INSERT IGNORE INTO ALERT_FUNCTION (ALERT_ID, ID_Function)
																				SELECT A.ALERT_ID, F.ID_Function FROM {function_metrics_table} AS F
																				INNER JOIN ALERT AS A ON F.ID_File = A.ID_File
																				WHERE A.ALERT_ID = %(ALERT_ID)s AND A.ALERT_LINE BETWEEN F.BeginLine AND F.EndLine;
																				''', params=alert_params)

										if not success:
											log.error(f'Failed to insert the functions IDs where the alert appears with the error code {error_code} and the parameters: {alert_params}.')

										success, error_code = db.execute_query(f'''
																				INSERT IGNORE INTO ALERT_CLASS (ALERT_ID, ID_Class)
																				SELECT A.ALERT_ID, C.ID_Class FROM {class_metrics_table} AS C
																				INNER JOIN ALERT AS A ON C.ID_File = A.ID_File
																				WHERE A.ALERT_ID = %(ALERT_ID)s AND A.ALERT_LINE BETWEEN C.BeginLine AND C.EndLine;
																				''', params=alert_params)

										if not success:
											log.error(f'Failed to insert the class IDs where the alert appears with the error code {error_code} and the parameters: {alert_params}.')

									else:
										log.error(f'Failed to insert the alert with the error code {error_code} and the parameters: {alert_params}.')

						##################################################

						if sat.database_name == 'Cppcheck':
							alerts = cppcheck.read_and_convert_output_csv_in_default_format(csv_file_path)
							
							for row in alerts.itertuples():

								alert_params = {}

								cwe_list = [row.CWE] if row.CWE is not None else []

								alert_params['RULE_NAME'] = row.Rule
								alert_params['RULE_CATEGORY'] = row.Severity

								alert_params['ALERT_SEVERITY_LEVEL'] = None
								alert_params['ALERT_LINE'] = row.Line
								alert_params['ALERT_MESSAGE'] = row.Message

								alert_params['FILE_PATH'] = row.File

								insert_alert(alert_params, cwe_list)

						elif sat.database_name == 'Flawfinder':
							alerts = flawfinder.read_and_convert_output_csv_in_default_format(csv_file_path)

							for row in alerts.itertuples():

								alert_params = {}

								# Get a list of CWEs. The following values may appear:
								# - ''
								# - 'CWE-676, CWE-120, CWE-20'
								# - 'CWE-362/CWE-367!'
								# - 'CWE-119!/CWE-120'
								cwe_list = cast(list, extract_numeric(row.CWEs, all=True)) if row.CWEs is not None else []

								alert_params['RULE_NAME'] = row.Name
								alert_params['RULE_CATEGORY'] = row.Category

								alert_params['ALERT_SEVERITY_LEVEL'] = row.Level
								alert_params['ALERT_LINE'] = row.Line
								alert_params['ALERT_MESSAGE'] = row.Warning

								alert_params['FILE_PATH'] = row.File

								insert_alert(alert_params, cwe_list)

						else:
							log.critical(f'Cannot insert the alerts from "{zip_file_path}" since the SAT "{sat.database_name}" is not recognized.')

						##################################################

						db.commit()
						
						delete_file(csv_file_path)

##################################################

insert_alerts_in_database()

log.info('Finished running.')
print('Finished running.')