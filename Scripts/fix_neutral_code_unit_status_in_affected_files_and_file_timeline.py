#!/usr/bin/env python3

"""
	This script updates the CSV files generated after running "find_affected_files.py" and "create_file_timeline.py" by changing the vulnerability
	status of any neutral code unit from 'Yes' to 'No'.
"""

import pandas as pd # type: ignore

from modules.common import log, deserialize_json_container, serialize_json_container
from modules.project import Project

####################################################################################################

total_rows = 0
total_functions = 0
total_classes = 0

def set_status_to_neutral(code_unit_list: list, is_function: bool) -> None:
	""" Sets the vulnerability status of a function or class to neutral if it was vulenrable. """

	global total_functions, total_classes

	for unit in code_unit_list:
		if unit['Vulnerable'] == 'Yes':
			unit.update({'Vulnerable': 'No'})

			if is_function:
				total_functions += 1
			else:
				total_classes += 1

project_list = Project.get_project_list_from_config()

for project in project_list:
	
	for input_csv_path in project.find_output_csv_files('affected-files'):

		log.info(f'Fixing the neutral code unit status for the project "{project}" using the information in "{input_csv_path}".')

		affected_files = pd.read_csv(input_csv_path, dtype=str)

		for index, row in affected_files.iterrows():

			neutral_function_list = deserialize_json_container(row['Neutral File Functions'], [])
			neutral_class_list = deserialize_json_container(row['Neutral File Classes'], [])

			set_status_to_neutral(neutral_function_list, True) # type: ignore[arg-type]
			set_status_to_neutral(neutral_class_list, False) # type: ignore[arg-type]

			affected_files.at[index, 'Neutral File Functions'] = serialize_json_container(neutral_function_list) # type: ignore[arg-type]
			affected_files.at[index, 'Neutral File Classes'] = serialize_json_container(neutral_class_list) # type: ignore[arg-type]

			total_rows += 1

		affected_files.to_csv(input_csv_path, index=False)

	for input_csv_path in project.find_output_csv_files('file-timeline'):

		log.info(f'Fixing the neutral code unit status for the project "{project}" using the information in "{input_csv_path}".')

		timeline = pd.read_csv(input_csv_path, dtype=str)

		is_neutral = (timeline['Affected'] == 'Yes') & (timeline['Vulnerable'] == 'No')

		for index, row in timeline[is_neutral].iterrows():

			neutral_function_list = deserialize_json_container(row['Affected Functions'], [])
			neutral_class_list = deserialize_json_container(row['Affected Classes'], [])

			set_status_to_neutral(neutral_function_list, True) # type: ignore[arg-type]
			set_status_to_neutral(neutral_class_list, False) # type: ignore[arg-type]

			timeline.at[index, 'Affected Functions'] = serialize_json_container(neutral_function_list) # type: ignore[arg-type]
			timeline.at[index, 'Affected Classes'] = serialize_json_container(neutral_class_list) # type: ignore[arg-type]

			total_rows += 1

		timeline.to_csv(input_csv_path, index=False)

result = f'Finished running. Updated {total_rows} rows including {total_functions} functions and {total_classes} classes.'
log.info(result)
print(result)
