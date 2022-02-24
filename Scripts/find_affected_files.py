#!/usr/bin/env python3

"""
	This script finds any files affected by vulnerabilities associated with the five C/C++ projects by querying their version control systems.
	
	This information includes the file's path, a list of CVEs, the Git commit where the vulnerability was patched (neutral), and the commit
	immediately before (vulnerable).

	This script uses the CSV files generated after running "collect_vulnerabilities.py" to creates its own CSVs.
"""

from typing import Any

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, check_range_overlap, deserialize_json_container, replace_in_filename, serialize_json_container
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:

	CSV_WRITE_FREQUENCY = GLOBAL_CONFIG['affected_files_csv_write_frequency']

	for input_csv_path in project.find_output_csv_files('cve'):

		output_csv_path = replace_in_filename(input_csv_path, 'cve', 'affected-files')

		log.info(f'Finding affected files for the project "{project}" using the information in "{input_csv_path}".')
		
		cves = pd.read_csv(input_csv_path, usecols=['CVE', 'Git Commit Hashes'], dtype=str)
		cves = cves.dropna()
		cves['Git Commit Hashes'] = cves['Git Commit Hashes'].map(deserialize_json_container)

		git_commit_hashes = cves['Git Commit Hashes'].tolist()
		neutral_commit_list = [commit_hash for hash_list in git_commit_hashes for commit_hash in hash_list]
		log.info(f'Found {len(neutral_commit_list)} total neutral commits.')

		neutral_commit_list = project.filter_git_commit_hashes_by_source_file_extensions(neutral_commit_list)
		neutral_commit_list = project.sort_git_commit_hashes_topologically(neutral_commit_list)
		log.info(f'Processing {len(neutral_commit_list)} neutral commits after filtering and sorting.')

		affected_files = pd.DataFrame(columns=[	'File Path', 'Topological Index', 'Parent Count',
												
												'Vulnerable Commit Hash', 'Vulnerable Tag Name', 'Vulnerable Author Date',
												'Vulnerable Changed Lines', 'Vulnerable File Functions', 'Vulnerable File Classes',

												'Neutral Commit Hash', 'Neutral Tag Name', 'Neutral Author Date',
												'Neutral Changed Lines', 'Neutral File Functions', 'Neutral File Classes',
												
												'CVEs', 'Last Change Commit Hashes'])

		for topological_index, neutral_commit_hash in enumerate(neutral_commit_list):

			vulnerable_commit_list = project.find_parent_git_commit_hashes(neutral_commit_hash)
			vulnerable_commit_list = project.sort_git_commit_hashes_topologically(vulnerable_commit_list)

			neutral_tag_name = project.find_tag_name_from_git_commit_hash(neutral_commit_hash)
			neutral_author_date = project.find_author_date_from_git_commit_hash(neutral_commit_hash)

			is_neutral_commit = cves['Git Commit Hashes'].map(lambda hash_list: neutral_commit_hash in hash_list)
			cve_list = cves.loc[is_neutral_commit, 'CVE'].tolist()
			cve_list = serialize_json_container(cve_list)

			vulnerable_changed_lines: Any
			neutral_changed_lines: Any
			for file_path, vulnerable_changed_lines, neutral_changed_lines in project.find_changed_source_files_and_lines_since_parent_git_commit(neutral_commit_hash):

				vulnerable_changed_lines = serialize_json_container(vulnerable_changed_lines)
				neutral_changed_lines = serialize_json_container(neutral_changed_lines)

				last_change_commit_list: Any
				last_change_commit_list = project.find_last_changed_git_commit_hashes(neutral_commit_hash, file_path)
				last_change_commit_list = serialize_json_container(last_change_commit_list)

				for vulnerable_commit_hash in vulnerable_commit_list:

					parent_count = len(vulnerable_commit_list)
					vulnerable_tag_name = project.find_tag_name_from_git_commit_hash(vulnerable_commit_hash)
					vulnerable_author_date = project.find_author_date_from_git_commit_hash(vulnerable_commit_hash)

					row = {
							'File Path': file_path,
							'Topological Index': topological_index,
							'Parent Count': parent_count,

							'Vulnerable Commit Hash': vulnerable_commit_hash,
							'Vulnerable Tag Name': vulnerable_tag_name,
							'Vulnerable Author Date': vulnerable_author_date,
							'Vulnerable Changed Lines': vulnerable_changed_lines,

							'Neutral Commit Hash': neutral_commit_hash,
							'Neutral Tag Name': neutral_tag_name,
							'Neutral Author Date': neutral_author_date,
							'Neutral Changed Lines': neutral_changed_lines,

							'CVEs': cve_list,
							'Last Change Commit Hashes': last_change_commit_list
					}

					affected_files = affected_files.append(row, ignore_index=True)

			# Update the results on disk periodically.
			if topological_index % CSV_WRITE_FREQUENCY == 0:
				log.info(f'Updating the results with basic commit information for topological index {topological_index}...')
				affected_files.to_csv(output_csv_path, index=False)

		# Since we need to parse the vulnerable and neutral version of each file, it's more convenient to perform
		# the Git checkouts after iterating over every commit.
		grouped_files = affected_files.groupby(by=['Topological Index', 'Vulnerable Commit Hash', 'Neutral Commit Hash'])
		for (topological_index, vulnerable_commit_hash, neutral_commit_hash), group_df in grouped_files:

			def checkout_affected_files_and_find_code_units(commit_hash: str, is_commit_vulnerable: bool) -> None:
				""" A helper method that performs the checkout and finds any affected functions and classes."""

				status = 'Vulnerable' if is_commit_vulnerable else 'Neutral'

				checkout_success = project.checkout_entire_git_commit(commit_hash)
				if checkout_success:

					for row in group_df.itertuples():

						file_path = row[1]
						function_list, class_list = project.find_code_units_in_file(file_path)

						changed_lines = row[7] if is_commit_vulnerable else row[13]
						changed_lines = deserialize_json_container(changed_lines, [])

						# Check whether the code units are actually vulnerable. A file in a vulnerable commit might
						# have five functions, but only one could be vulnerable.
						for unit in function_list + class_list:
							was_unit_changed = is_commit_vulnerable and any(check_range_overlap(unit['Lines'], line_range) for line_range in changed_lines)
							unit_status = 'Yes' if was_unit_changed else 'No'
							unit.update({'Vulnerable': unit_status})

						affected_files.at[row.Index, f'{status} File Functions'] = serialize_json_container(function_list)
						affected_files.at[row.Index, f'{status} File Classes'] = serialize_json_container(class_list)
				else:
					log.error(f'Failed to checkout the commit {commit_hash} ({status}).')

			checkout_affected_files_and_find_code_units(vulnerable_commit_hash, True)
			checkout_affected_files_and_find_code_units(neutral_commit_hash, False)

			# Update the results on disk periodically.
			if topological_index % CSV_WRITE_FREQUENCY == 0:
				log.info(f'Updating the results with function and class information for topological index {topological_index}...')
				affected_files.to_csv(output_csv_path, index=False)

		affected_files.to_csv(output_csv_path, index=False)
		project.hard_reset_git_head()

	log.info(f'Finished running for the project "{project}".')

print('Finished running.')
