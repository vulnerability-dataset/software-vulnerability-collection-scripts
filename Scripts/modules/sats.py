#!/usr/bin/env python3

"""
	This module defines any classes that represent third-party tools used to perform static analysis on a project's source files.
"""

import os
import subprocess
import tempfile
from collections import namedtuple
from typing import cast, Optional, Tuple, Union

import bs4 # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore

from .common import log, GLOBAL_CONFIG, delete_directory, delete_file, extract_numeric, get_path_in_data_directory
from .project import Project

####################################################################################################

class Sat():
	""" Represents a third-party static analysis tool (SAT) and allows the execution of its commands. """

	config: dict

	name: str
	executable_path: str
	version: Optional[str]

	project: Project

	def __init__(self, name: str, project: Project):

		self.config = GLOBAL_CONFIG['sats'][name]
		self.name = name
		self.executable_path = self.config['executable_path']
		self.version = None
		self.project = project

	def __str__(self):
		return self.name

	def get_version(self) -> str:
		""" Gets the tool's version number. """
		return self.version or 'Unknown'

	def run(self, *args) -> Tuple[bool, str]:
		""" Runs the tool with a series of command line arguments. """

		if self.executable_path is None:
			return (False, '')

		arguments = [self.executable_path] + [arg for arg in args]
		result = subprocess.run(arguments, capture_output=True, text=True)
		success = (result.returncode == 0)

		if not success:
			command_line_arguments = ' '.join(arguments)
			error_message = result.stderr or result.stdout
			log.error(f'Failed to run the command "{command_line_arguments}" with the error code {result.returncode} and the error message "{error_message}".')

		return (success, result.stdout)

	@staticmethod
	def write_list_to_temporary_file(value_list: list) -> Optional[str]:
		""" Writes a list to a temporary file, where each item appears in its own line. If this file cannot be created, this function returns None.
		This file is closed before returning so it can be opened by other processes. For example, passing a list of file paths to a SAT. """

		result = None

		try:
			_, temporary_file_path = tempfile.mkstemp()

			with open(temporary_file_path, 'w') as temporary_file:
				for value in value_list:
					temporary_file.write(value + '\n')

			result = temporary_file_path

		except Exception as error:
			log.error(f'Failed to write the list to a temporary file with the error: {repr(error)}')

		return result

	@staticmethod
	def get_sat_info_from_config() -> list:
		""" Creates a list of SAT information given the current configuration. """

		template_list = list(GLOBAL_CONFIG['sats'].values())
		SatInfo = namedtuple('SatInfo', template_list[0]) # type: ignore[misc]
		
		sat_list = []
		for name, items in GLOBAL_CONFIG['sats'].items():
			
			sat_database_name = items['database_name']
			if sat_database_name is not None:

				should_be_allowed = GLOBAL_CONFIG['allowed_sats'].get(sat_database_name)
				
				if should_be_allowed:
					info = SatInfo(**items) # type: ignore[call-arg]
					sat_list.append(info)
				else:
					log.info(f'Ignoring the SAT "{sat_database_name}".')

		return sat_list

####################################################################################################

class UnderstandSat(Sat):
	""" Represents the Understand tool, which is used to generate software metrics given a project's source files. """

	use_new_database_format: bool
	database_extension: str

	def __init__(self, project: Project):
		super().__init__('Understand', project)
		
		version_success, build_number = self.run('version')
		if version_success:

			build_number = cast(str, extract_numeric(build_number))
			self.version = build_number
			
			self.use_new_database_format = int(build_number) >= 1039 # Understand 6.0 or later.
			self.database_extension = '.und' if self.use_new_database_format else '.udb'

			log.info(f'Loaded {self} version {self.version}.')

	def generate_project_metrics(self, file_path_list: Union[list, bool], output_csv_path: str) -> bool:
		""" Generates the project's metrics using the files and any other options defined in the database directory. """
	
		"""
			Understand Metrics Settings:
			- WriteColumnTitles				on/off (default on)
			- ShowFunctionParameterTypes	on/off (default off)
			- ShowDeclaredInFile			on/off (default off)
			- FileNameDisplayMode			NoPath/FullPath/RelativePath (default NoPath)
			- DeclaredInFileDisplayMode		NoPath/FullPath/RelativePath (default NoPath)
			- OutputFile					<CSV File Path> (default "<Database Name>.csv")
			
			These were listed using the command: und list -all settings <Database Name>
		"""

		success = False
		database_path = os.path.join(self.project.output_directory_path, self.project.short_name + self.database_extension)

		if isinstance(file_path_list, bool):
			file_path_list = [self.project.repository_path]

		# Understand fails if one of the files doesn't exist on disk so we'll filter the paths before running it.
		filtered_file_path_list = []
		for file_path in file_path_list:

			if os.path.isfile(file_path):
				filtered_file_path_list.append(file_path)
			else:
				log.warning(f'Skipping the file path "{file_path}" since it does not exist on disk.')

		file_path_list = filtered_file_path_list
		del filtered_file_path_list

		temporary_file_path = Sat.write_list_to_temporary_file(file_path_list)

		if temporary_file_path:

			success, _ = self.run	(
										'-quiet', '-db', database_path,
										'create', '-languages', 'c++', # This value cannot be self.project.language since only "c++" is accepted.
										'settings', '-metrics', 'all',
													'-metricsWriteColumnTitles', 'on',
													'-metricsShowFunctionParameterTypes', 'on',
													'-metricsShowDeclaredInFile', 'on',
													'-metricsFileNameDisplayMode', 'NoPath',
													'-metricsDeclaredInFileDisplayMode', 'FullPath', # See below.
													'-metricsOutputFile', output_csv_path,

										'add', f'@{temporary_file_path}',
										'analyze',
										'metrics'
									)

			delete_file(temporary_file_path)

		# Safeguard against the tool executing successfully without having created the CSV file.
		success = success and os.path.isfile(output_csv_path)

		if success:
			
			try:
				metrics = pd.read_csv(output_csv_path, dtype=str)
			except pd.errors.ParserError as error:
				log.warning(f'Could not parse the metrics in "{output_csv_path}" with the error: {repr(error)}')
				metrics = pd.read_csv(output_csv_path, dtype=str, error_bad_lines=False, warn_bad_lines=True)

			# Ideally, we'd just set the "DeclaredInFileDisplayMode" option to "RelativePath" and skip this step. However, doing that would
			# lead to a few cases where the relative path to the file in the repository was incorrect.
			metrics['File'] = metrics['File'].map(lambda x: self.project.get_relative_path_in_repository(x) if pd.notna(x) else x)

			metrics.to_csv(output_csv_path, index=False)

		if self.use_new_database_format:
			delete_directory(database_path)
		else:
			delete_file(database_path)

		return success

####################################################################################################

class CppcheckSat(Sat):
	""" Represents the Cppcheck tool, which is used to generate security alerts given a project's source files. """

	RULE_TO_CWE: dict = {}
	mapped_rules_to_cwes: bool = False

	def __init__(self, project: Project):
		super().__init__('Cppcheck', project)

		version_success, version_number = self.run('--version')
		if version_success:
			self.version = cast(Optional[str], extract_numeric(version_number, r'\d+\.\d+'))
			log.info(f'Loaded {self} version {self.version}.')

		if not CppcheckSat.mapped_rules_to_cwes:
			CppcheckSat.mapped_rules_to_cwes = True

			error_list_file_path = get_path_in_data_directory('cppcheck_error_list.xml')

			with open(error_list_file_path) as xml_file:
				error_soup = bs4.BeautifulSoup(xml_file, 'xml')

			if error_soup is not None:
				error_list = error_soup.find_all('error', id=True, cwe=True)				
				CppcheckSat.RULE_TO_CWE = {error['id']: error['cwe'] for error in error_list}
			else:
				log.error(f'Failed to map a list of SAT rules in "{error_list_file_path}" to their CWE values.')

	def generate_project_alerts(self, file_path_list: Union[list, bool], output_csv_path: str) -> bool:
		""" Generates the project's alerts given list of files. """

		success = False

		if self.project.include_directory_path is not None:
			include_arguments = ['-I', self.project.include_directory_path]
		else:
			include_arguments = ['--suppress=missingInclude']

		if isinstance(file_path_list, bool):
			file_path_list = [self.project.repository_path]

		temporary_file_path = Sat.write_list_to_temporary_file(file_path_list)

		if temporary_file_path:

			# The argument "--enable=error" is not necessary since it's enabled by default.
			# @Future: Should "--force" be used? If so, remove "--suppress=toomanyconfigs".
			success, _ = self.run	(
										'--quiet',
										'--enable=warning,portability', '--inconclusive',
										f'--language={self.project.language}', *include_arguments,
										'--suppress=toomanyconfigs', '--suppress=unknownMacro', '--suppress=unmatchedSuppression',
										
										'--template="{file}","{line}","{column}","{severity}","{id}","{cwe}","{message}"',
										f'--output-file={output_csv_path}',
										f'--file-list={temporary_file_path}'
								)

			delete_file(temporary_file_path)

		# Safeguard against the tool executing successfully without having created the CSV file.
		success = success and os.path.isfile(output_csv_path)

		if success:

			alerts = pd.read_csv(output_csv_path, header=None, names=['File', 'Line', 'Column', 'Severity', 'Rule', 'CWE', 'Message'], dtype=str)

			alerts['File'] = alerts['File'].map(lambda x: None if x == 'nofile' else self.project.get_relative_path_in_repository(x))
			alerts['Line'] = alerts['Line'].replace({'0': None})
			alerts['Column'] = alerts['Column'].replace({'0': None})
			alerts['CWE'] = alerts['CWE'].replace({'0': None})

			alerts.to_csv(output_csv_path, index=False)

		return success

	def read_and_convert_output_csv_in_default_format(self, csv_file_path: str) -> pd.DataFrame:
		""" Reads a CSV file generated using Cppcheck's default output parameters and converts it to a more convenient format. """

		# The default CSV files generated by Cppcheck don't quote values with commas correctly.
		# This means that pd.read_csv() would fail because some lines have more columns than others.
		# We'll read each line ourselves and interpret anything after the fourth column as being part
		# of the "Message" column. Format: "[FILE]:[LINE],[SEVERITY],[RULE],[MESSAGE]"
		dictionary_list = []
		with open(csv_file_path, 'r') as csv_file:

			for line in csv_file:
				
				# Some rare cases showed only "Segmentation fault (core dumped)" in the line.
				if not ':' in line:
					continue

				# We'll assume that a source file's path never has a colon so we don't accidentally
				# break paths with commas. In some rare cases the following can appear as the first
				# value: ":,[ETC]". Since there's no file path or line number, we'll discard it below.
				file_path = line_number = severity = rule = message = None
				file_path, remaining_line = line.split(':', 1)
				if remaining_line:
					line_number, severity, rule, message = remaining_line.split(',', 3)
					message = message.rstrip()

				dictionary_list.append({'File': file_path, 'Line': line_number, 'Severity': severity, 'Rule': rule, 'Message': message})

		alerts = pd.DataFrame.from_dict(dictionary_list, dtype=str)
		alerts = alerts.replace({np.nan: None, '': None})
		alerts.dropna(subset=['File', 'Line'], inplace=True)

		alerts['File'] = alerts['File'].map(lambda x: None if x == 'nofile' else self.project.get_relative_path_in_repository(x))
		alerts['CWE'] = alerts['Rule'].map(lambda x: CppcheckSat.RULE_TO_CWE.get(x, None))
		
		return alerts

####################################################################################################

class FlawfinderSat(Sat):
	""" Represents the Flawfinder tool, which is used to generate security alerts given a project's source files. """

	def __init__(self, project: Project):
		super().__init__('Flawfinder', project)

		version_success, version_number = self.run('--version')
		if version_success:
			self.version = version_number.strip()
			log.info(f'Loaded {self} version {self.version}.')

	def generate_project_alerts(self, file_path_list: Union[list, bool], output_csv_path: str) -> bool:
		""" Generates the project's alerts given list of files. """
		raise NotImplementedError('Cannot yet generate alerts using Flawfinder.')

	def read_and_convert_output_csv_in_default_format(self, csv_file_path: str) -> pd.DataFrame:
		""" Reads a CSV file generated using Flawfinder's default output parameters and converts it to a more convenient format. """

		alerts = pd.read_csv(csv_file_path, dtype=str)
		alerts.dropna(subset=['File', 'Line', 'Level', 'Category', 'Name'], inplace=True)
		alerts = alerts.replace({np.nan: None})
	
		alerts['File'] = alerts['File'].map(lambda x: self.project.get_relative_path_in_repository(x))

		return alerts

if __name__ == '__main__':
	pass