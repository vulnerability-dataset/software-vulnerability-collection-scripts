#!/usr/bin/env python3

"""
	This script creates a timeline of files starting at each project's first commit and going through every commit that was affected
	by a vulnerability.

	This script uses the CSV files generated after running "find_affected_files.py" to creates its own CSVs.
"""

from collections import namedtuple

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, deserialize_json_container, lists_have_elements_in_common, replace_in_filename, serialize_json_container
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

CSV_WRITE_FREQUENCY = GLOBAL_CONFIG['affected_files_csv_write_frequency']

for project in project_list:

	for input_csv_path in project.find_output_csv_files('affected-files'):

		log.info(f'Creating the file timeline for the project "{project}" using the information in "{input_csv_path}".')

		affected_files = pd.read_csv(input_csv_path, dtype=str)

		unique_commits = affected_files.drop_duplicates(subset=['Vulnerable Commit Hash', 'Neutral Commit Hash'])
		vulnerable_commit_list = unique_commits['Vulnerable Commit Hash'].tolist()
		neutral_commit_list = unique_commits['Neutral Commit Hash'].tolist()

		assert len(vulnerable_commit_list) == len(neutral_commit_list), f'The number of vulnerable ({len(vulnerable_commit_list)}) and neutral ({len(neutral_commit_list)}) commits must be the same.'

		Commit = namedtuple('Commit', ['TopologicalIndex', 'Vulnerable', 'CommitHash', 'TagName', 'AuthorDate', 'Cves'])
		topological_index = 0

		def create_commit_tuple(commit_hash: str, vulnerable: bool) -> Commit:

			tag_name = project.find_tag_name_from_git_commit_hash(commit_hash)
			author_date = project.find_author_date_from_git_commit_hash(commit_hash)

			status = 'Vulnerable' if vulnerable else 'Neutral'
			is_affected = affected_files[f'{status} Commit Hash'] == commit_hash
			
			if is_affected.any():
				file = affected_files[is_affected].iloc[0]
				cves = file['CVEs']
			else:
				cves = None

			global topological_index
			commit = Commit(topological_index, vulnerable, commit_hash, tag_name, author_date, cves)
			topological_index += 1

			return commit

		first_commit = project.find_first_git_commit_hash()
		commit_list = [create_commit_tuple(first_commit, False)]

		for vulnerable_commit, neutral_commit in zip(vulnerable_commit_list, neutral_commit_list):

			commit_list.append(create_commit_tuple(vulnerable_commit, True))
			commit_list.append(create_commit_tuple(neutral_commit, False))

		timeline = pd.DataFrame(columns=[	'File Path', 'Topological Index',
											'Affected', 'Vulnerable', 'Commit Hash',
											'Tag Name', 'Author Date',
											'Changed Lines', 'Affected Functions', 'Affected Classes', 'CVEs'])
		
		output_csv_path = replace_in_filename(input_csv_path, 'affected-files', 'file-timeline')

		for index, (from_commit, to_commit) in enumerate(zip(commit_list, commit_list[1:])):

			if GLOBAL_CONFIG['start_at_timeline_index'] is not None and index < GLOBAL_CONFIG['start_at_timeline_index']:
				continue

			assert (from_commit.Vulnerable and not to_commit.Vulnerable) or (not from_commit.Vulnerable and to_commit.Vulnerable)

			for file_path, from_changed_lines, to_changed_lines in project.find_changed_source_files_and_lines_between_git_commits(from_commit.CommitHash, to_commit.CommitHash):

				if to_commit.Vulnerable:

					is_affected = (affected_files['File Path'] == file_path) & (affected_files['Vulnerable Commit Hash'] == to_commit.CommitHash)

					# Skip any vulnerable files that are listed in the previous neutral commit. If we kept these files, we would classify the same file
					# as being both neutral and vulnerable, when it's in fact the latter.
					if is_affected.any():
						log.info(f'Skipping the file "{file_path}" in the neutral commit {from_commit.CommitHash} since it will be vulnerable in the next commit {to_commit.CommitHash}.')
						continue

				first_row = {
					'File Path': file_path,
					'Topological Index': from_commit.TopologicalIndex,
					'Affected': 'Yes' if from_commit.Vulnerable else 'No',
					'Vulnerable': 'Yes' if from_commit.Vulnerable else 'No',
					'Commit Hash': from_commit.CommitHash,
					'Tag Name': from_commit.TagName,
					'Author Date': from_commit.AuthorDate,
					'Changed Lines': serialize_json_container(from_changed_lines),
				}

				second_row = None

				if from_commit.Vulnerable:

					is_affected = (affected_files['File Path'] == file_path) & (affected_files['Vulnerable Commit Hash'] == from_commit.CommitHash)
					
					if is_affected.any():
						file = affected_files[is_affected].iloc[0]
						vulnerable_functions = file['Vulnerable File Functions']
						vulnerable_classes = file['Vulnerable File Classes']
						neutral_functions = file['Neutral File Functions']
						neutral_classes = file['Neutral File Classes']
					else:
						log.warning(f'The affected file "{file_path}" has no entry associated with the vulnerable commit {from_commit.CommitHash} ({from_commit.TopologicalIndex}).')
						vulnerable_functions = None
						vulnerable_classes = None
						neutral_functions = None
						neutral_classes = None

					first_row['Affected Functions'] = vulnerable_functions
					first_row['Affected Classes'] = vulnerable_classes
					first_row['CVEs'] = from_commit.Cves

					second_row = {
						'File Path': file_path,
						'Topological Index': to_commit.TopologicalIndex,
						'Affected': 'Yes',
						'Vulnerable': 'No',
						'Commit Hash': to_commit.CommitHash,
						'Tag Name': to_commit.TagName,
						'Author Date': to_commit.AuthorDate,
						'Changed Lines': serialize_json_container(to_changed_lines),
						'Affected Functions': neutral_functions,
						'Affected Classes': neutral_classes,
						'CVEs': to_commit.Cves,
					}
					
				timeline = timeline.append(first_row, ignore_index=True)
				if second_row is not None:
					timeline = timeline.append(second_row, ignore_index=True)

			if index % CSV_WRITE_FREQUENCY == 0:
				log.info(f'Updating the results for the index {index} ({from_commit.AuthorDate})...')
				timeline.to_csv(output_csv_path, index=False)

		timeline.drop_duplicates(subset=['File Path', 'Topological Index', 'Affected'], inplace=True)

		# Remove any vulnerable files that are listed in neutral commits which turned out to be vulnerable in the next index. We will only do this
		# if both the neutral and vulnerable indexes are associated with the same vulnerability (CVE). If we kept these files, we would classify
		# the same file as being both neutral and vulnerable, when it's in fact the latter.

		log.info('Locating any consecutive commits.')

		timeline['Next Commit Hash'] = timeline['Commit Hash'].shift(-1)
		timeline['Next Vulnerable'] = timeline['Vulnerable'].shift(-1)

		is_consecutive_commit = (timeline['Commit Hash'] == timeline['Next Commit Hash']) & (timeline['Vulnerable'] != timeline['Next Vulnerable'])
		is_consecutive_commit |= is_consecutive_commit.shift(1)

		consecutive_commits = timeline[is_consecutive_commit].iterrows()

		for (neutral_index, neutral_row), (vulnerable_index, vulnerable_row) in zip(consecutive_commits, consecutive_commits):

			commit_hash = neutral_row['Commit Hash']
			assert commit_hash == vulnerable_row['Commit Hash']

			neutral_topological_index = neutral_row['Topological Index']
			vulnerable_topological_index = vulnerable_row['Topological Index']

			neutral_cve_list = deserialize_json_container(neutral_row['CVEs'])
			vulnerable_cve_list = deserialize_json_container(vulnerable_row['CVEs'])

			if lists_have_elements_in_common(neutral_cve_list, vulnerable_cve_list): # type: ignore[arg-type]

				is_neutral = timeline['Topological Index'] == neutral_topological_index
				is_vulnerable = timeline['Topological Index'] == vulnerable_topological_index

				neutral_files = timeline.loc[is_neutral, 'File Path']
				vulnerable_files = timeline.loc[is_vulnerable, 'File Path']

				files_in_common = neutral_files[neutral_files.isin(vulnerable_files)]
				timeline.drop(files_in_common.index, inplace=True)

				log.info(f'Removed {len(files_in_common)} neutral files that were actually vulnerable between the consecutive commits {neutral_topological_index} and {vulnerable_topological_index} ({commit_hash}): {files_in_common.tolist()}')

			else:
				log.info(f'The consecutive commits {neutral_topological_index} and {vulnerable_topological_index} ({commit_hash}) do not have vulnerabilities in common: "{neutral_cve_list}" vs "{vulnerable_cve_list}".')

		timeline.drop(columns=['Next Commit Hash', 'Next Vulnerable'], inplace=True)
		timeline.to_csv(output_csv_path, index=False)
		
	log.info(f'Finished running for the project "{project}".')

print('Finished running.')
