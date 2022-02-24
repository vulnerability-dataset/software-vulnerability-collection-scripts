#!/usr/bin/env python3

"""
	This scripts verifies the output of "generate_metrics.py" by checking if each commit has at least one metrics CSV file associated with it.
"""

import os
import re
from typing import Union

import pandas as pd # type: ignore

from modules.common import log, extract_numeric
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

for project in project_list:

	for input_csv_path in project.find_output_csv_files('file-timeline'):
		
		log.info(f'Verifying the metrics from the project "{project}" using the metrics and the information in "{input_csv_path}".')

		timeline = pd.read_csv(input_csv_path, usecols=['Topological Index'], dtype=int)
		expected_num_commits = timeline['Topological Index'].max() + 1
		total_num_commits = timeline['Topological Index'].nunique()

		index_list = []

		for metrics_csv_path in project.find_output_csv_files('metrics', subdirectory='metrics'):

			filename = os.path.basename(metrics_csv_path)
			topological_index = extract_numeric(filename, r'-t(\d+)-', convert=True)
			index_list.append(topological_index)

		missing_index_list: Union[list, set]
		missing_index_list = set(range(0, expected_num_commits)).difference(index_list)
		missing_index_list = sorted(missing_index_list)

		result = f'There are {len(missing_index_list)} missing topological indexes for the project "{project}" (in the timeline, {expected_num_commits} were expected and {total_num_commits} exist in total): {missing_index_list}'
		log.info(result)
		print(result)