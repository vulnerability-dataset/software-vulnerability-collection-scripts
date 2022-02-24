#!/usr/bin/env python3

"""
	This module defines a class that represents a C/C++ project and that contains methods for interfacing with its vulnerabilities and source files.
"""

import glob
import json
import os
import random
import re
import sys
from collections import defaultdict, namedtuple
from typing import Callable, Iterator, List, Optional, Tuple, Union

import bs4 # type: ignore
import clang.cindex # type: ignore
import git # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore
from clang.cindex import CursorKind, TranslationUnitLoadError # type: ignore

from .common import log, GLOBAL_CONFIG, DEBUG_ENABLED, DEBUG_CONFIG, CURRENT_TIMESTAMP, change_datetime_string_format, deserialize_json_container, format_unix_timestamp, join_and_normalize_paths
from .cve import Cve
from .scraping import ScrapingManager, ScrapingRegex

####################################################################################################

CLANG_INDEX: clang.cindex.Index

try:
	clang_lib_path = GLOBAL_CONFIG['clang_lib_path']
	log.info(f'Loading libclang from "{clang_lib_path}".')
	
	try:
		clang.cindex.Config.set_library_path(clang_lib_path)
		CLANG_INDEX = clang.cindex.Index.create()
	except Exception as error:
		clang.cindex.Config.set_library_file(clang_lib_path)
		CLANG_INDEX = clang.cindex.Index.create()

	log.info(f'Loaded libclang successfully.')

except Exception as error:
	log.error(f'Failed to load libclang with the error: {repr(error)}')

####################################################################################################

class Project:
	""" Represents a software project, its repository, and the vulnerabilities it's affected by. """

	full_name: str
	short_name: str
	database_id: int
	database_name: str
	github_data_name: str
	vendor_id: int
	product_id: int
	url_pattern: str
	repository_path: str
	repository_base_name: str
	master_branch: str
	language: str
	include_directory_path: Optional[str]

	SOURCE_FILE_EXTENSIONS: list = ['c', 'cpp', 'cc', 'cxx', 'c++', 'cp', 'h', 'hpp', 'hh', 'hxx']
	SOURCE_FILE_EXTENSIONS_WITH_WILDCARDS: list = ['*.' + extension for extension in SOURCE_FILE_EXTENSIONS] 

	repository: git.Repo

	output_directory_path: str
	scrape_all_branches: bool

	def __init__(self, project_name: str, project_info: dict):
		
		self.full_name = project_name
		for key, value in project_info.items():
			setattr(self, key, value)

		self.repository_base_name = os.path.basename(self.repository_path)

		self.output_directory_path = os.path.join(self.output_directory_path, self.short_name)
		self.output_directory_path = os.path.abspath(self.output_directory_path)

		try:
			self.repository = git.Repo(self.repository_path)
			log.info(f'Loaded the project "{self}" located in "{self.repository_path}".')
		except Exception as error:
			self.repository = None
			log.error(f'Failed to get the repository for the project "{self}"" with the error: {repr(error)}')
		
		if self.include_directory_path is not None:
			self.include_directory_path = join_and_normalize_paths(self.repository_path, self.include_directory_path)

	def __str__(self):
		return self.full_name

	####################################################################################################

	"""
		Methods used to initialize or perform basic operations used by all projects.
	"""

	@staticmethod
	def get_project_list_from_config(config: dict = GLOBAL_CONFIG) -> list:
		""" Creates a list of projects given the current configuration. """

		output_directory_path = config['output_directory_path']
		scrape_all_branches = config['scrape_all_branches']
		project_config = config['projects']

		project_list = []
		for full_name, info in project_config.items():

			short_name = info['short_name']

			should_be_allowed = GLOBAL_CONFIG['allowed_projects'].get(short_name)
			if not should_be_allowed:
				log.info(f'Ignoring the project "{full_name}" ({short_name}).')
				continue

			info['output_directory_path'] = output_directory_path
			info['scrape_all_branches'] = scrape_all_branches
			project: Project
		
			log.info(f'Loading the project "{full_name}" ({short_name}) with the following configurations: {info}')

			if short_name == 'mozilla':
				project = MozillaProject(full_name, info)
			elif short_name == 'xen':
				project = XenProject(full_name, info)
			elif short_name == 'apache':
				project = ApacheProject(full_name, info)
			elif short_name == 'glibc':
				project = GlibcProject(full_name, info)
			else:
				project = Project(full_name, info)

			project_list.append(project)

		return project_list

	@staticmethod
	def debug_ensure_all_project_repositories_were_loaded(project_list: list):
		""" Terminates the program if one or more projects are missing their repositories. This method does nothing outside debug mode. """

		if DEBUG_ENABLED:
			for project in project_list:
				if project.repository is None:
					log.critical(f'The repository for project "{project}" was not loaded correctly.')
					sys.exit(1)

	def get_base_output_csv_path(self, prefix: str) -> str:
		""" Creates the base output path for a CSV file with a given prefix. For example, using the prefix "cve" for the Mozilla project,
		the file path would be: "cve-1-mozilla-master-branch-20210401212440.csv". """
		used_branches = 'all-branches' if self.scrape_all_branches else 'master-branch'
		filename = prefix + f'-{self.database_id}-{self.short_name}-{used_branches}-{CURRENT_TIMESTAMP}.csv'
		return os.path.join(self.output_directory_path, filename)

	def find_output_csv_files(self, prefix: str, subdirectory: Optional[str] = None, sort_key: Optional[Callable] = None) -> List[str]:
		""" Finds the paths to any CSV files that belong to this project by looking at their prefix. """
		
		csv_path = self.output_directory_path

		if subdirectory is not None:
			csv_path = os.path.join(csv_path, subdirectory)

		csv_path = os.path.join(csv_path, fr'{prefix}*-{self.database_id}-{self.short_name}-*')
		csv_file_list = glob.glob(csv_path)
		csv_file_list = sorted(csv_file_list, key=sort_key)

		return csv_file_list

	def create_output_subdirectory(self, subdirectory: str = '') -> None:
		""" Creates a subdirectory in the project's output directory. """
		path = os.path.join(self.output_directory_path, subdirectory)
		os.makedirs(path, exist_ok=True)

	####################################################################################################

	"""
		Methods used to interface with a project's repository.
	"""

	def get_absolute_path_in_repository(self, relative_path: str) -> str:
		""" Converts the relative path of a file in the project's repository into an absolute one. """
		full_path = os.path.join(self.repository_path, relative_path)
		return os.path.normpath(full_path)

	def get_relative_path_in_repository(self, full_path: str) -> str:
		""" Converts the absolute path of a file in the project's repository into a relative one. """

		path = full_path.replace('\\', '/')

		try:
			_, path = path.split(self.repository_base_name + '/', 1)			
		except ValueError:
			pass

		return path

	def find_full_git_commit_hash(self, short_commit_hash: str) -> Optional[str]:
		""" Finds the full Git commit hash given the short hash. """

		if self.repository is None:
			return None

		try:
			# git show --format="%H" --no-patch [SHORT HASH]
			full_commit_hash = self.repository.git.show(short_commit_hash, format='%H', no_patch=True)
		except git.exc.GitCommandError as error:
			full_commit_hash = None
			log.error(f'Failed to find the full version of the commit hash "{short_commit_hash}" with the error: {repr(error)}')

		return full_commit_hash

	def find_git_commit_hashes_from_pattern(self, grep_pattern: str) -> list:
		""" Finds any Git commit hashes whose title and message match a given regex pattern. """

		if self.repository is None:
			return []

		try:
			# git log --all --format="%H" --grep="[REGEX]" --regexp-ignore-case --extended-regexp
			# The --extended-regexp option enables the following special characters: ? + { | ( )
			log_result = self.repository.git.log(all=True, format='%H', grep=grep_pattern, regexp_ignore_case=True, extended_regexp=True)
			hash_list = log_result.splitlines()
		except git.exc.GitCommandError as error:
			hash_list = []
			log.error(f'Failed to find commit hashes using the pattern "{grep_pattern}" with the error: {repr(error)}')

		return hash_list

	def is_git_commit_hash_valid(self, commit_hash: str) -> bool:
		""" Checks if a Git commit hash exists in the repository. """

		if self.repository is None:
			return False

		try:
			# git branch --contains [HASH]
			self.repository.git.branch(contains=commit_hash)
			is_valid = True
		except git.exc.GitCommandError as error:
			is_valid = False

		return is_valid	

	def remove_invalid_git_commit_hashes(self, cve: Cve):
		""" Removes any invalid Git commit hashes from a CVE. """

		if self.repository is not None:
			cve.git_commit_hashes = [hash for hash in cve.git_commit_hashes if self.is_git_commit_hash_valid(hash)]

	def is_git_commit_hash_in_master_branch(self, commit_hash: str) -> bool:
		""" Checks if a Git commit hash exists in the repository's master branch. """

		if self.repository is None:
			return False

		is_master = False

		try:
			# git branch --contains [HASH] --format="%(refname:short)"
			branch_result = self.repository.git.branch(contains=commit_hash, format='%(refname:short)')
			is_master = self.master_branch in branch_result.splitlines()

		except git.exc.GitCommandError as error:
			# If there's no such commit in the repository.
			pass

		return is_master
	
	def remove_git_commit_hashes_by_branch(self, cve: Cve):
		""" Removes any Git commit hashes from a CVE that do not exist in the master branch. If the configuration file specified every branch,
		this method does nothing. """

		if self.repository is not None and not self.scrape_all_branches:
			cve.git_commit_hashes = [hash for hash in cve.git_commit_hashes if self.is_git_commit_hash_in_master_branch(hash)]

	def sort_git_commit_hashes_topologically(self, hash_list: List[str]) -> List[str]:
		""" Sorts a list of Git commit hashes topologically from oldest to newest. """

		if self.repository is None:
			return []

		if len(hash_list) <= 1:
			return hash_list

		try:
			# git rev-list --topo-order --reverse --no-walk=sorted [HASH 1] [...] [HASH N]
			rev_list_result = self.repository.git.rev_list(*hash_list, topo_order=True, reverse=True, no_walk='sorted')
			hash_list = rev_list_result.splitlines()

		except git.exc.GitCommandError as error:
			# If there's no such commit in the repository.
			log.error(f'Found one or more invalid commits while trying to sort the commit hashes topologically with the error: {repr(error)}')
			hash_list = []

		return hash_list

	def filter_git_commit_hashes_by_source_file_extensions(self, hash_list: List[str]) -> List[str]:
		""" Filters a list of Git commit hashes so that only commits related to C/C++ files remain."""

		if self.repository is None:
			return []

		try:
			# git rev-list [HASH 1] [...] [HASH N] -- [FILE EXTENSION 1] [...] [FILE EXTENSION N]
			rev_list_result = self.repository.git.rev_list(*hash_list, '--', *Project.SOURCE_FILE_EXTENSIONS_WITH_WILDCARDS, no_walk='unsorted')
			hash_list = rev_list_result.splitlines()

		except git.exc.GitCommandError as error:
			hash_list = []
			log.error(f'Failed to filter the commit hashes with the error: {repr(error)}')
			
		return hash_list

	def find_changed_source_files_and_lines_between_git_commits(self, from_commit: str, to_commit: str) -> Iterator[ Tuple[str, List[List[int]], List[List[int]]] ]:
		""" Finds the paths and modified lines of any C/C++ source files that were changed between two commits."""

		if self.repository is None:
			return

		try:
			# git diff --unified=0 [HASH FROM] [HASH TO] -- [FILE EXTENSION 1] [...] [FILE EXTENSION N]
			# For the parent commit: git diff --unified=0 [HASH]^ [HASH] -- [FILE EXTENSION 1] [...] [FILE EXTENSION N]
			diff_result = self.repository.git.diff(from_commit, to_commit, '--', *Project.SOURCE_FILE_EXTENSIONS_WITH_WILDCARDS, unified=0)

		except git.exc.GitCommandError as error:
			log.error(f'Failed to find the changed sources files and lines from the commit {from_commit} to {to_commit} with the error: {repr(error)}')
			return

		last_file_path: Optional[str] = None
		last_from_lines_list: List[List[int]] = []
		last_to_lines_list: List[List[int]] = []
	
		def yield_last_file_if_it_exists() -> Iterator[ Tuple[str, List[List[int]], List[List[int]]] ]:
			""" Yields the previously found file path and its changed lines. """

			nonlocal last_file_path, last_from_lines_list, last_to_lines_list

			if last_file_path is not None:			
				yield (last_file_path, last_from_lines_list, last_to_lines_list)
				last_file_path = None
				last_from_lines_list = []
				last_to_lines_list = []

		for line in diff_result.splitlines():

			# E.g. "+++ b/embedding/components/windowwatcher/src/nsPrompt.cpp"
			if line.startswith('+++ '):

				yield from yield_last_file_if_it_exists()
				_, last_file_path = line.split('/', 1)

				if last_file_path == 'dev/null':
					last_file_path = None
				
			# E.g. "@@ -451,2 +428,2 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,"
			# E.g. "@@ -263 +255,0 @@ do_test (int argc, char *argv[])"
			elif last_file_path is not None and line.startswith('@@'):

				match = ScrapingRegex.GIT_DIFF_LINE_NUMBERS.search(line)
				if match:

					def append_line_numbers(line_list: List[List[int]], begin_group_name: str, total_group_name: str) -> None:

						line_begin = int(match.group(begin_group_name)) # type: ignore[union-attr]

						if line_begin == 0:
							return

						total_lines = match.group(total_group_name) # type: ignore[union-attr]
						total_lines = int(total_lines) if total_lines is not None else 1

						line_end = line_begin + max(total_lines - 1, 0)

						line_list.append( [line_begin, line_end] )

					append_line_numbers(last_from_lines_list, 'from_begin', 'from_total')
					append_line_numbers(last_to_lines_list, 'to_begin', 'to_total')

				else:
					log.error(f'Could not find the line number information for the file "{last_file_path}" (from {from_commit} to {to_commit}) in the diff line: "{line}".')

		yield from yield_last_file_if_it_exists()

		"""
			E.g. for Mozilla: git diff --unified=0 a714da4a56957c826a7cafa381c4d8df832172f2 a714da4a56957c826a7cafa381c4d8df832172f2^

			diff --git a/embedding/components/windowwatcher/src/nsPrompt.cpp b/embedding/components/windowwatcher/src/nsPrompt.cpp
			index a782689cc853..f95e19ed7c97 100644
			--- a/embedding/components/windowwatcher/src/nsPrompt.cpp
			+++ b/embedding/components/windowwatcher/src/nsPrompt.cpp
			@@ -58,3 +57,0 @@
			-#include "nsIPrefService.h"
			-#include "nsIPrefLocalizedString.h"
			-
			@@ -424,20 +420,0 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,
			-  // Trim obnoxiously long realms.
			-  if (realm.Length() > 150) {
			- [...]
			-  }
			@@ -451,2 +428,2 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,
			-  NS_NAMED_LITERAL_STRING(proxyText, "EnterLoginForProxy");
			-  NS_NAMED_LITERAL_STRING(originText, "EnterLoginForRealm");
			+  NS_NAMED_LITERAL_STRING(proxyText, "EnterUserPasswordForProxy");
			+  NS_NAMED_LITERAL_STRING(originText, "EnterUserPasswordForRealm");
		"""

	def find_changed_source_files_and_lines_since_parent_git_commit(self, commit_hash: str) -> Iterator[ Tuple[str, List[List[int]], List[List[int]]] ]:
		""" Finds the paths and modified lines of any C/C++ source files that were changed since the previous commit."""
		yield from self.find_changed_source_files_and_lines_between_git_commits(commit_hash + '^', commit_hash)

	def find_changed_source_files_in_parent_git_commit(self, commit_hash: str) -> Iterator[str]:
		"""" Finds the paths of any C/C++ source files that were changed since the previous commit."""

		if self.repository is None:
			return

		try:
			# git diff --name-only [HASH]^ [HASH] -- [FILE EXTENSION 1] [...] [FILE EXTENSION N]
			diff_result = self.repository.git.diff(commit_hash + '^', commit_hash, '--', *Project.SOURCE_FILE_EXTENSIONS_WITH_WILDCARDS, name_only=True)
			
			for file_path in diff_result.splitlines():
				yield file_path

		except git.exc.GitCommandError as error:
			log.error(f'Failed to find the changed sources files from the commit "{commit_hash}" with the error: {repr(error)}')
			return

	def list_all_source_file_git_commit_hashes(self) -> List[str]:
		""" Lists all Git commit hashes between two dates where at least one C/C++ file was changed. This list is ordered topologically from oldest to newest. """

		if self.repository is None:
			return []

		after_date = GLOBAL_CONFIG['neutral_after_author_date']
		before_date = GLOBAL_CONFIG['neutral_before_author_date']
		
		hash_list = []

		try:
			# git log --topo-order --reverse --do-walk --format="%H %as" -- [FILE EXTENSION 1] [...] [FILE EXTENSION N]
			log_result = self.repository.git.log('--', *Project.SOURCE_FILE_EXTENSIONS_WITH_WILDCARDS, topo_order=True, reverse=True, do_walk=True, format='%H %as')
			
			for line in log_result.splitlines():
				
				# We have to do this manually instead of using the --after and --before options since those use
				# the commit date, and not the author date. The dates we compare use the YYYY-MM-DD format.
				commit_hash, date = line.split(maxsplit=1)
				if after_date <= date <= before_date:
					hash_list.append(commit_hash)

		except git.exc.GitCommandError as error:
			log.error(f'Failed to list all commit hashes between "{after_date}" and "{before_date}" with the error: {repr(error)}')

		return hash_list

	def find_first_git_commit_hash(self) -> Optional[str]:
		""" Finds the first Git commit hash in a repository. """

		if self.repository is None:
			return None

		try:
			# git log --topo-order --reverse --do-walk --format="%H" --
			log_result = self.repository.git.log('--', topo_order=True, reverse=True, do_walk=True, format='%H')
			commit_hash = log_result.splitlines()[0]
		except git.exc.GitCommandError as error:
			commit_hash = None
			log.error(f'Failed to find the first commit hash with the error: {repr(error)}')

		return commit_hash

	def find_last_changed_git_commit_hashes(self, commit_hash: str, file_path: str) -> List[str]:
		""" Finds any previous Git commit hashes where a given file was last changed. """

		if self.repository is None:
			return []

		try:
			# git log [HASH] --parents --max-count=1 --format="%P" -- [FILE PATH]
			commit_list = self.repository.git.log(commit_hash, '--', file_path, parents=True, max_count=1, format='%P')
			commit_list = commit_list.split()
		except git.exc.GitCommandError as error:
			commit_list = []
			log.error(f'Failed to find the parent of the commit hash "{commit_hash}" with the error: {repr(error)}')

		return commit_list

	def find_parent_git_commit_hashes(self, commit_hash: str) -> List[str]:
		""" Finds any previous Git commit hashes. """
		return self.find_last_changed_git_commit_hashes(commit_hash, '.')

	def find_tag_name_from_git_commit_hash(self, commit_hash: str) -> Optional[str]:
		""" Finds the tag name associated with a Git commit hash. """

		if self.repository is None:
			return None

		try:
			# git name-rev --tags --name-only [HASH]
			# E.g. "v4.4-rc6~22^2~24" or "v2.6.39-rc3^0" or "undefined"
			name_rev_result = self.repository.git.name_rev(commit_hash, tags=True, name_only=True)
			tag_name = re.split(r'~|\^', name_rev_result, 1)[0]
		except git.exc.GitCommandError as error:
			tag_name = None
			log.error(f'Failed to find the tag name for the commit hash "{commit_hash}" with the error: {repr(error)}')

		return tag_name

	def find_author_date_from_git_commit_hash(self, commit_hash: str) -> Optional[str]:
		""" Finds the author date (not the commit date) associated with a Git commit hash. """

		if self.repository is None:
			return None

		try:
			# git log --format="%ad" --date="unix" [HASH]
			log_result = self.repository.git.log(commit_hash, format='%ad', date='unix')
			timestamp = log_result.split('\n', 1)[0]
			date = format_unix_timestamp(timestamp)
		except git.exc.GitCommandError as error:
			date = None
			log.error(f'Failed to find the author date for the commit hash "{commit_hash}" with the error: {repr(error)}')

		return date

	def checkout_files_in_git_commit(self, commit_hash: str, file_path_list: list) -> bool:
		""" Performs the Git checkout operation on a specific list of files in a given Git commit. """

		if self.repository is None:
			return False

		success = False

		try:
			# git checkout [COMMIT] -- [FILE PATH 1] [FILE PATH 2] [...] [FILE PATH N]
			self.repository.git.checkout(commit_hash, '--', *file_path_list)
			success = True
		except git.exc.GitCommandError as error:
			log.error(f'Failed to checkout the files in commit "{commit_hash}" with the error: {repr(error)}')
			
		return success

	def checkout_entire_git_commit(self, commit_hash: str) -> bool:
		""" Performs the Git checkout operation for every file in a given Git commit. """
		return self.checkout_files_in_git_commit(commit_hash, ['.'])

	def hard_reset_git_head(self):
		""" Performs a hard reset operation to the project's repository. """

		if self.repository is None:
			return

		try:
			# git reset --hard
			self.repository.git.reset(hard=True)
		except git.exc.GitCommandError as error:
			log.error(f'Failed to hard reset the current HEAD with the error: {repr(error)}')

	####################################################################################################

	"""
		Methods used to scrape vulnerability metadata from sources like online databases, bug trackers,
		security advisories, and the project's version control system.
	"""

	def scrape_additional_information_from_security_advisories(self, cve: Cve):
		""" Scrapes any additional information from the project's security advisories. This method should be overriden by a project's subclass. """
		pass

	def scrape_additional_information_from_version_control(self, cve: Cve):
		""" Scrapes any additional information from the project's version control system. This method should be overriden by a project's subclass. """
		pass

	def scrape_vulnerabilities_from_cve_details(self) -> Iterator[Cve]:
		""" Scrapes any vulnerabilities related to this project from the CVE Details website. """

		log.info(f'Collecting the vulnerabilities for the "{self}" project ({self.vendor_id}, {self.product_id}):')
		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page('https://www.cvedetails.com/vulnerability-list.php', {'vendor_id': self.vendor_id, 'product_id': self.product_id})

		if response is None:
			log.error('Could not download the first hub page. No vulnerabilities will be scraped for this project.')
			return
		
		main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

		page_div = main_soup.find('div', id='pagingb')
		page_a_list = page_div.find_all('a', title=ScrapingRegex.PAGE_TITLE)
		page_url_list = ['https://www.cvedetails.com' + page_a['href'] for page_a in page_a_list]

		if DEBUG_ENABLED:
			previous_len = len(page_url_list)
			if previous_len > DEBUG_CONFIG['min_hub_pages']:
				page_url_list = page_url_list[::DEBUG_CONFIG['hub_page_step']]
			
			log.debug(f'Reduced the number of hub pages from {previous_len} to {len(page_url_list)}.')

		else:
			first_page = GLOBAL_CONFIG.get('start_at_cve_hub_page')
			if first_page is not None:
				log.info(f'Starting at hub page {first_page} at the user\'s request.')
				page_url_list = page_url_list[first_page-1:]

		for i, page_url in enumerate(page_url_list):

			log.info(f'Scraping hub page {i+1} of {len(page_url_list)}...')
			page_response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(page_url)
			if page_response is None:
				log.error(f'Failed to download hub page {i+1}.')
				continue
	
			page_soup = bs4.BeautifulSoup(page_response.text, 'html.parser')
			vulnerability_table = page_soup.find('table', id='vulnslisttable')
			cve_a_list = vulnerability_table.find_all('a', title=ScrapingRegex.CVE)
			
			# Test a random sample of CVEs from each page.
			if DEBUG_ENABLED:
				previous_len = len(cve_a_list)
				if DEBUG_CONFIG['use_random_sampling']:
					cve_a_list = random.sample(cve_a_list, DEBUG_CONFIG['max_cves_per_hub_page'])
				else:
					cve_a_list = cve_a_list[:DEBUG_CONFIG['max_cves_per_hub_page']]
				log.debug(f'Reduced the number of CVE pages from {previous_len} to {len(cve_a_list)}.')

			for j, cve_a in enumerate(cve_a_list):

				cve_id = cve_a.get_text(strip=True)
				cve = Cve(cve_id, self)

				log.info(f'Scraping the CVE page {j+1} of {len(cve_a_list)}: "{cve.id}" from "{cve.url}"...')
				download_success = cve.download_cve_details_page()
				
				if download_success:
					cve.scrape_dates_from_page()
					cve.scrape_basic_attributes_from_page()
					cve.scrape_affected_product_versions_from_page()
					cve.scrape_references_from_page()

					self.scrape_additional_information_from_security_advisories(cve)
					self.scrape_additional_information_from_version_control(cve)

					cve.remove_duplicated_values()
					self.remove_invalid_git_commit_hashes(cve)
					self.remove_git_commit_hashes_by_branch(cve)
				else:
					log.error(f'Failed to download the page for {cve}.')

				yield cve

	####################################################################################################

	"""
		Methods used to find any files, functions, and classes affected by a project's vulnerabilities.
	"""

	def find_code_units_in_file(self, file_path: str) -> Tuple[ List[dict], List[dict] ]:
		""" Lists any functions and classes in a source file in the project's repository. """

		function_list: List[dict] = []
		class_list: List[dict] = []

		source_file_path = self.get_absolute_path_in_repository(file_path)
		source_file_name = os.path.basename(source_file_path)

		try:
			with open(source_file_path, 'r', encoding='utf-8', errors='replace') as source_file:
				source_contents = source_file.read()
				if self.language == 'c++':
					# @Hack: This is a hacky way of getting clang to report C++ methods that belong to a class
					# that is not defined in the file that we're processing. Although we tell clang where to
					# look for the header files that define these classes, this wouldn't work for the Mozilla's
					# repository structure. By removing the "<Class Name>::" pattern from a function's definition,
					# we're essentially telling clang to consider them regular C-style functions. This works for
					# our purposes since we only care about a function's name and its beginning and ending line
					# numbers.
					source_contents = re.sub(r'\S+::', '', source_contents)

		except Exception as error:
			log.error(f'Failed to read the source file "{source_file_path}" with the error: {repr(error)}')
			return (function_list, class_list)

		try:
			clang_arguments = ['--language', self.language]
			
			if self.include_directory_path is not None:
				clang_arguments.extend(['--include-directory', self.include_directory_path])

			global CLANG_INDEX
			tu = CLANG_INDEX.parse(source_file_name, args=clang_arguments, unsaved_files=[ (source_file_name, source_contents) ])
			
			if DEBUG_ENABLED:
				for diagnostic in tu.diagnostics:
					log.debug(f'Diagnostic: {diagnostic}')

			FUNCTION_KINDS = [	CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD, CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR,
								CursorKind.CONVERSION_FUNCTION, CursorKind.FUNCTION_TEMPLATE]

			CLASS_KINDS = [CursorKind.STRUCT_DECL, CursorKind.UNION_DECL, CursorKind.CLASS_DECL, CursorKind.CLASS_TEMPLATE]

			KINDS_TO_NAME = {CursorKind.STRUCT_DECL: 'Struct', CursorKind.UNION_DECL: 'Union', CursorKind.CLASS_DECL: 'Class', CursorKind.CLASS_TEMPLATE: 'Class'}

			for node in tu.cursor.walk_preorder():

				# This should have the same behavior as clang_Location_isFromMainFile().
				if node.location.file is not None and node.location.file.name == source_file_name and node.is_definition():

					def add_to_list(code_unit_list: List[dict]):
						""" Helper method that adds the code unit's properties to the resulting list. """						
						
						unit_lines = [node.extent.start.line, node.extent.end.line]
						code_unit_info = {'Name': node.spelling, 'Signature': node.displayname, 'Lines': unit_lines}

						kind_name = KINDS_TO_NAME.get(node.kind)
						if kind_name is not None:
							code_unit_info.update({'Kind': kind_name})

						code_unit_list.append(code_unit_info)

					if node.kind in FUNCTION_KINDS:
						add_to_list(function_list)
					elif node.kind in CLASS_KINDS:
						add_to_list(class_list)

		except TranslationUnitLoadError as error:
			log.error(f'Failed to parse the source file "{source_file_path}" with the error: {repr(error)}')

		return (function_list, class_list)

	def iterate_and_checkout_file_timeline_in_repository(self, csv_file_path: str) -> Iterator[tuple]:
		""" Iterates over and performs a Git checkout operation on a list of files affected by the project's vulnerabilities.
		
		For each neutral-vulnerable commit pair, the commit hash and vulnerability status are different, but the file list is the same
		since it only uses the information relative to the neutral commit, even for the vulnerable one."""

		timeline = pd.read_csv(csv_file_path, usecols=[	'File Path', 'Topological Index', 'Affected', 'Vulnerable',
														'Commit Hash', 'Affected Functions', 'Affected Classes', 'CVEs'], dtype=str)

		timeline = timeline.replace({np.nan: None})
		timeline['Topological Index'] = pd.to_numeric(timeline['Topological Index'])
		
		if GLOBAL_CONFIG['start_at_checkout_commit_index'] is not None:
			
			is_allowed_commit = timeline['Topological Index'] >= GLOBAL_CONFIG['start_at_checkout_commit_index']
			timeline = timeline[is_allowed_commit]

		filter_commit_using_config = {}
		if GLOBAL_CONFIG['checkout_commit_index_list'] is not None:

			filter_commit_using_config = {topological_index: True for topological_index in GLOBAL_CONFIG['checkout_commit_index_list']}

			allowed_commit_list = []
			for topological_index in GLOBAL_CONFIG['checkout_commit_index_list']:
				allowed_commit_list.append(topological_index)
				allowed_commit_list.append(topological_index + 1)
				allowed_commit_list.append(topological_index + 2)

			is_allowed_commit = timeline['Topological Index'].isin(allowed_commit_list)
			timeline = timeline[is_allowed_commit]

		grouped_files = timeline.groupby(by=['Topological Index', 'Affected', 'Vulnerable', 'Commit Hash', 'CVEs'], dropna=False)

		ChangedFiles = namedtuple('ChangedFiles', [	'TopologicalIndex', 'Affected', 'Vulnerable', 'CommitHash', 'Cves',
													'AbsoluteFilePaths', 'RelativeFilePaths', 'FilePathToFunctions', 'FilePathToClasses'])

		for (topological_index, affected, vulnerable, commit_hash, cves), group_df in grouped_files:

			if filter_commit_using_config and not filter_commit_using_config.get(topological_index):
				continue

			# For any file in an affected commit (vulnerable or neutral), we know that their paths exist in that particular commit.
			# When we look at the files that weren't affected, we are now dealing with multiple changes across different commits.
			# Because of this, we must checkout the next commit (i.e. the next vulnerable commit) so that we can guarantee that
			# those files exist. For example, if we checked out the first commit in the project, we would be missing any files
			# that were added or changed between that commit and the next vulnerable one.

			affected = (affected == 'Yes')

			if affected:
				commit_hash_to_checkout = commit_hash

			else:
				is_next_commit = (timeline['Topological Index'] == topological_index + 1) | (timeline['Topological Index'] == topological_index + 2)
				
				if is_next_commit.any():
					next_group = timeline[is_next_commit].iloc[0]
					commit_hash_to_checkout = next_group['Commit Hash']
				else:
					log.warning(f'Defaulting to the current commit hash {commit_hash}.')
					commit_hash_to_checkout = commit_hash

			checkout_success = self.checkout_entire_git_commit(commit_hash_to_checkout)
			if checkout_success:

				vulnerable = (vulnerable == 'Yes')
				if pd.isna(cves):
					cves = None

				relative_file_path_list: list = group_df['File Path'].tolist()
				absolute_file_path_list = [self.get_absolute_path_in_repository(file_path) for file_path in relative_file_path_list]
				
				affected_function_list = group_df['Affected Functions'].tolist()
				affected_function_list = [deserialize_json_container(function_list) for function_list in affected_function_list]

				affected_class_list = group_df['Affected Classes'].tolist()
				affected_class_list = [deserialize_json_container(class_list) for class_list in affected_class_list]

				def map_file_paths_to_code_units(code_unit_list: list) -> dict:
					""" Maps the relative file paths in the repository to their code units. """

					# It's possible that the SATs generate metrics or alerts related to files that we're not currently
					# iterating over (e.g. the header files of the current C/C++ source file). In those cases, we won't
					# have a list of code units.
					file_path_to_code_units = defaultdict(lambda: [])
					for file_path, units in zip(relative_file_path_list, code_unit_list):
						if units is not None:
							file_path_to_code_units[file_path] = units

					return file_path_to_code_units

				file_path_to_functions = map_file_paths_to_code_units(affected_function_list)
				file_path_to_classes = map_file_paths_to_code_units(affected_class_list)

				yield ChangedFiles(	topological_index, affected, vulnerable, commit_hash, cves,
									absolute_file_path_list, relative_file_path_list, file_path_to_functions, file_path_to_classes)

			else:
				log.error(f'Failed to checkout the commit {commit_hash_to_checkout} in the CSV file "{csv_file_path}".')
		
		self.hard_reset_git_head()

####################################################################################################

class MozillaProject(Project):
	""" Represents the Mozilla project. """

	MOZILLA_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.mozilla.org')

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Mozilla Foundation Security Advisories (MFSA) pages.
		for mfsa_id, mfsa_url in zip(cve.advisory_ids, cve.advisory_urls):

			mfsa_info = {}
			log.info(f'Scraping additional information from advisory page {mfsa_id}: "{mfsa_url}"...')

			mfsa_response = MozillaProject.MOZILLA_SCRAPING_MANAGER.download_page(mfsa_url)
			if mfsa_response is None:
				log.error(f'Could not download the page for {mfsa_id}.')
				continue

			mfsa_soup = bs4.BeautifulSoup(mfsa_response.text, 'html.parser')

			"""
			[MFSA 2005-01 until (present)]
			<dl class="summary">
				<dt>Announced</dt>
				<dd>November 20, 2012</dd>
				<dt>Reporter</dt>
				<dd>Mariusz Mlynski</dd>
				<dt>Impact</dt>
				<dd><span class="level critical">Critical</span></dd>
				<dt>Products</dt>
				<dd>Firefox, Firefox ESR</dd>
				<dt>Fixed in</dt>
				<dd>
					<ul>
						<li>Firefox 17</li>
						<li>Firefox ESR 10.0.11</li>
					</ul>
				</dd>
			</dl>

			MFSA 2005-01 until MFSA 2016-84]
			<h3>References</h3>

			<p>Crashes referencing removed nodes (Jesse Ruderman, Martijn Wargers)</p>
			<ul>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=338391">https://bugzilla.mozilla.org/show_bug.cgi?id=338391</a></li>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=340733">https://bugzilla.mozilla.org/show_bug.cgi?id=340733</a></li>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=338129">https://bugzilla.mozilla.org/show_bug.cgi?id=338129</a></li>
			</ul>

			<p>crypto.generateCRMFRequest callback can run on deleted context (shutdown)</p>
			<ul>
				<li>
					<a href="https://bugzilla.mozilla.org/show_bug.cgi?id=337462">https://bugzilla.mozilla.org/show_bug.cgi?id=337462</a>
					<br>CVE-2006-3811
				</li>
			</ul>

			[MFSA 2016-85 until (present)]
			<section class="cve">
				<h4 id="CVE-2018-12359" class="level-heading">
					<a href="#CVE-2018-12359"><span class="anchor">#</span>CVE-2018-12359: Buffer overflow using computed size of canvas element</a>
				</h4>
				<dl class="summary">
					<dt>Reporter</dt>
					<dd>Nils</dd>
					<dt>Impact</dt>
					<dd><span class="level critical">critical</span></dd>
				</dl>
				<h5>Description</h5>
				<p>A buffer overflow can occur when rendering canvas content while adjusting the height and width of the <code>&lt;canvas&gt;</code> element dynamically, causing data to be written outside of the currently computed boundaries. This results in a potentially exploitable crash.</p>
				<h5>References</h5>
				<ul>
					<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1459162">Bug 1459162</a></li>
				</ul>
			</section>

			<section class="cve">
				[...]
			</section>								
			"""

			# Get the basic information for all MFSA layout versions.
			dl_summary = mfsa_soup.find('dl', class_='summary')
			if dl_summary is not None:

				dt_list = dl_summary.find_all('dt')
				dd_list = dl_summary.find_all('dd')
				for dt, dd in zip(dt_list, dd_list):

					key = dt.get_text(strip=True)
					value = dd.get_text(strip=True)

					# Change the format of specific fields so they're consistent with the rest of the CSV file.
					if key == 'Announced':
						value = change_datetime_string_format(value, '%B %d, %Y', '%Y-%m-%d', 'en_US.UTF-8')
					elif key == 'Impact':
						value = value.title()
					elif key == 'Products':
						value = [product.strip() for product in value.split(',')]
					elif key == 'Fixed in':
						value = [li.get_text(strip=True) for li in dd.find_all('li')]
					
					key = key.title()
					mfsa_info[key] = value
			else:
				log.warning(f'No summary description list found for {mfsa_id}.')

			# Get the CVE information for all MFSA layout versions.
			cve_list = []

			# --> For MFSA 2005-01 until MFSA 2016-84.
			h3_list = mfsa_soup.find_all('h3')
			for h3 in h3_list:

				h3_text = h3.get_text(strip=True)
				if h3_text == 'References':

					for li in h3.find_all_next('li'):
						
						li_text = li.get_text(strip=True)
						match = ScrapingRegex.CVE.search(li_text)
						if match:
							cve_list.append(match.group(1))

			# --> For MFSA 2005-01 until the latest page.
			section_list = mfsa_soup.find_all('section', class_='cve')
			for section in section_list:
				h4_cve = section.find('h4', id=ScrapingRegex.CVE)
				if h4_cve is not None:
					cve_list.append(h4_cve['id'])

			if cve_list:
				mfsa_info['CVEs'] = cve_list

			cve.advisory_info[mfsa_id] = mfsa_info

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.bugzilla_ids:
			# E.g. " Bug 945192 - Followup to support Older SDKs in loaddlls.cpp. r=bbondy a=Sylvestre"
			regex_id = re.escape(id)
			grep_pattern = fr'^Bug \b{regex_id}\b'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class XenProject(Project):
	""" Represents the Xen project. """

	XEN_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://xenbits.xen.org')

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Xen Security Advisories (XSA) pages.
		for xsa_full_id, xsa_url in zip(cve.advisory_ids, cve.advisory_urls):
			
			xsa_info = {}
			xsa_id = xsa_full_id.rsplit('-')[-1]
			log.info(f'Scraping additional information from advisory page {xsa_full_id}: "{xsa_url}"...')
			
			xsa_response = XenProject.XEN_SCRAPING_MANAGER.download_page(xsa_url)
			if xsa_response is not None:

				xsa_soup = bs4.BeautifulSoup(xsa_response.text, 'html.parser')

				"""
				<table>
					<tbody>
						<tr>
							<th>Advisory</th>
							<td><a href="advisory-55.html">XSA-55</a></td>
						</tr>
						<tr>
							<th>Public release</th>
							<td>2013-06-03 16:18</td>
						</tr>
						<tr>
							<th>Updated</th>
							<td>2013-06-20 10:26</td>
						</tr>
						<tr>
							<th>Version</th>
							<td>5</td>
						</tr>
						<tr>
							<th>CVE(s)</th>
							<td><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2194">CVE-2013-2194</a> <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2195">CVE-2013-2195</a> <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2196">CVE-2013-2196</a></td>
						</tr>
						<tr>
							<th>Title</th>
							<td>Multiple vulnerabilities in libelf PV kernel handling</td>
						</tr>
					</tbody>
				</table>
				"""

				xsa_info_table = xsa_soup.find('table')
				if xsa_info_table is not None:

					xsa_info_th = xsa_info_table.find_all('th')
					xsa_info_td = xsa_info_table.find_all('td')
					for th, td in zip(xsa_info_th, xsa_info_td):

						key = th.get_text(strip=True)
						value = td.get_text(strip=True)

						# Change the format of specific fields so they're consistent with the rest of the CSV file.
						if key == 'Advisory':
							continue
						elif key == 'CVE(s)':
							key = 'CVEs'
							value = [cve_a.get_text(strip=True) for cve_a in td.find_all('a')]
						else:
							key = key.title()
							
						xsa_info[key] = value

					cve.advisory_info[xsa_full_id] = xsa_info

				else:
					log.warning(f'No information table found for {xsa_full_id}.')

			else:
				log.error(f'Could not download the page for {xsa_full_id}.')

			##################################################

			# Download an additional page that contains this XSA's Git commit hashes.
			xsa_meta_url = f'https://xenbits.xen.org/xsa/xsa{xsa_id}.meta'
			log.info(f'Scraping commit hashes from the metadata file related to {xsa_full_id}: "{xsa_meta_url}"...')
			
			xsa_meta_response = XenProject.XEN_SCRAPING_MANAGER.download_page(xsa_meta_url)
			if xsa_meta_response is not None:

				"""
				"Recipes":
				{
					"4.5":
					{
						"XenVersion": "4.5",
						"Recipes":
						{
							"xen":
							{
								"StableRef": "83724d9f3ae21a3b96362742e2f052b19d9f559a",
								"Prereqs": [],
								"Patches": ["xsa237-4.5/*"]
							}
						}
					},

					[...]
				}
				"""

				try:
					xsa_metadata = json.loads(xsa_meta_response.text)
				except json.decoder.JSONDecodeError as error:
					xsa_metadata = None
					log.error(f'Failed to parse the JSON metadata for {xsa_full_id} with the error: {repr(error)}')

				def nested_get(dictionary: dict, key_list: list):
					""" Tries to get a value from variously nested dictionaries by following a sequence of keys in a given order.
					If any intermediate dictionary doesn't exist, this method returns None. """

					value = None
					for key in key_list:
						value = dictionary.get(key)
						
						if value is None:
							break
						elif isinstance(value, dict):
							dictionary = value

					return value

				if xsa_metadata is not None:

					# Find every commit hash in the 'Recipes' dictionary.
					for reciple_key, recipe_value in xsa_metadata['Recipes'].items():

						commit_hash = nested_get(recipe_value, ['Recipes', 'xen', 'StableRef'])

						if commit_hash is not None:
							cve.git_commit_hashes.append(commit_hash)
						else:
							log.error(f'Could not find any commit hash for {xsa_full_id} in the "{reciple_key}" branch.')

			else:
				log.error(f'Could not download the metadata file for {xsa_full_id}.')

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.advisory_ids:
			# E.g. "This is CVE-2015-4164 / XSA-136."
			# E.g. "This is XSA-136 / CVE-2015-4164."
			# E.g. "This is XSA-215."
			regex_cve = re.escape(str(cve))
			regex_id = re.escape(id)
			grep_pattern = fr'This is.*\b({regex_cve}|{regex_id})\b'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class ApacheProject(Project):
	""" Represents the Apache HTTP Server project. """

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_version_control(self, cve: Cve):
		# E.g. "SECURITY: CVE-2017-3167 (cve.mitre.org)"
		# E.g. "Merge r1642499 from trunk: *) SECURITY: CVE-2014-8109 (cve.mitre.org)"
		regex_cve = re.escape(str(cve))
		grep_pattern = fr'SECURITY:.*\b{regex_cve}\b'
		hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
		cve.git_commit_hashes.extend(hashes)

####################################################################################################

class GlibcProject(Project):
	""" Represents the GNU C Library (glibc) project. """

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.bugzilla_ids:
			# E.g. "Don't ignore too long lines in nss_files (BZ #17079)"
			# E.g. "Fix integer overflows in internal memalign and malloc [BZ #22343] [BZ #22774]"
			# E.g. "Fix nan functions handling of payload strings (bug 16961, bug 16962)."
			# E.g.  Don't ignore too long lines in nss_files (BZ17079, CVE-2015-5277) Tested:
			regex_id = re.escape(id)
			grep_pattern = fr'((BZ|Bug).*\b{regex_id}\b)|(\bBZ{regex_id}\b)'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

if __name__ == '__main__':
	pass