#!/usr/bin/env python3

"""
	This script lists any neutral commits affected by vulnerabilities associated with the five C/C++ projects.
	
	This script uses the CSV files generated after running "find_affected_files.py" to creates its own CSVs.
"""

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, replace_in_filename
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:
	for input_csv_path in project.find_output_csv_files('affected-files'):

		log.info(f'Finding neutral commits for the project "{project}" using the information in "{input_csv_path}".')
		
		neutral_commits = pd.read_csv(input_csv_path, usecols=['Neutral Commit Hash', 'Neutral Author Date'], dtype=str)
		neutral_commits.drop_duplicates(subset='Neutral Commit Hash', inplace=True)
		
		after_date = GLOBAL_CONFIG['neutral_after_author_date']
		before_date = GLOBAL_CONFIG['neutral_before_author_date']
		is_between_dates = (after_date <= neutral_commits['Neutral Author Date']) & (neutral_commits['Neutral Author Date'] <= before_date)
		neutral_commits = neutral_commits[is_between_dates]

		neutral_commits.rename(columns={'Neutral Commit Hash': 'commit'}, inplace=True, errors='raise')
		neutral_commits.drop(columns='Neutral Author Date', inplace=True)
		neutral_commits.insert(1, 'status', 0)

		output_csv_path = replace_in_filename(input_csv_path, '-files', f'-commits-{after_date}-to-{before_date}')
		neutral_commits.to_csv(output_csv_path, index=False)

	log.info(f'Finished running for the project "{project}".')
	
print('Finished running.')
