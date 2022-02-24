#!/usr/bin/env python3

"""
	This module defines any general purpose functionalities used by all scripts, including functions for logging information, loading configuration
	files, and serializing data.
"""

import glob
import itertools
import json
import locale
import logging
import os
import re
import shutil
import sys
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, List, Optional, Union

import pandas as pd # type: ignore

####################################################################################################

PACKAGE_DIRECTORY_PATH = os.path.dirname(os.path.abspath(__file__))

def get_path_in_data_directory(short_file_path: str) -> str:
	""" Gets the absolute path of a file inside the data directory relative to this script. """
	return os.path.join(PACKAGE_DIRECTORY_PATH, 'data', short_file_path)

def get_current_timestamp() -> str:
	""" Gets the current timestamp as a string using the format "YYYYMMDDhhmmss". """
	return datetime.now(tz=timezone.utc).strftime('%Y%m%d%H%M%S')

CURRENT_TIMESTAMP = get_current_timestamp()

####################################################################################################

def add_log_file_handler(log: logging.Logger) -> None:
	""" Creates and adds a handle for logging information to a file. """

	LOG_DIRECTORY_PATH = os.path.join(PACKAGE_DIRECTORY_PATH, 'logs')
	os.makedirs(LOG_DIRECTORY_PATH, exist_ok=True)
	log_file_path = os.path.join(LOG_DIRECTORY_PATH, f'{CURRENT_TIMESTAMP}.log')

	handler = logging.FileHandler(log_file_path, 'w', 'utf-8')
	handler.setLevel(logging.DEBUG)
	formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)d] %(funcName)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
	handler.setFormatter(formatter)

	log.addHandler(handler)

def add_log_stream_handler(log: logging.Logger) -> None:
	""" Creates and adds a handle for logging information to a stream. """

	handler = logging.StreamHandler()
	handler.setLevel(logging.ERROR)
	formatter = logging.Formatter('%(funcName)s: %(message)s\n')
	handler.setFormatter(formatter)

	log.addHandler(handler)

def create_logger() -> logging.Logger:
	""" Creates a stream and file logger that is shared by all scripts that import this module. """

	log = logging.getLogger(__name__)
	log.setLevel(logging.INFO)
	add_log_file_handler(log)
	add_log_stream_handler(log)

	return log

####################################################################################################

log = create_logger()
log.info(f'Initializing the common module.')

####################################################################################################

def load_config_file(filename: str) -> dict:
	""" Loads a JSON configuration file. """

	CONFIG_DIRECTORY_PATH = os.path.join(PACKAGE_DIRECTORY_PATH, 'config')
	file_path = os.path.join(CONFIG_DIRECTORY_PATH, filename)

	try:
		with open(file_path) as file:
			config = json.loads(file.read())
	except Exception as error:
		config = {}
		log.error(f'Failed to load the JSON configuration file "{filename}" with the error: {repr(error)}')
		
	return config

def load_global_config() -> dict:
	""" Creates the main configuration dictionary by loading and merging the static and dynamic JSON configuration files. """

	static_config = load_config_file('static_config.json')
	dynamic_config = load_config_file('dynamic_config.json')

	def merge_dictionaries(dict_1: dict, dict_2: dict) -> dict:
		""" Merges two dictionaries, including any nested ones. """

		result = deepcopy(dict_1)

		for key, value_2 in dict_2.items():

			value_1 = result.get(key)

			if isinstance(value_1, dict) and isinstance(value_2, dict):
				result[key] = merge_dictionaries(value_1, value_2)
			else:
				result[key] = deepcopy(value_2)

		return result

	return merge_dictionaries(static_config, dynamic_config)

####################################################################################################

GLOBAL_CONFIG = load_global_config()
if not GLOBAL_CONFIG:
	log.critical(f'The module will terminate since no configuration options were found.')
	sys.exit(1)

DEBUG_CONFIG = GLOBAL_CONFIG['debug']
DEBUG_ENABLED = DEBUG_CONFIG['enabled']
DATABASE_CONFIG = GLOBAL_CONFIG['database']

if DEBUG_ENABLED:
	log.setLevel(logging.DEBUG)
	log.debug(f'Debug mode is enabled with the following options: {DEBUG_CONFIG}')

if GLOBAL_CONFIG['recursion_limit'] is not None:
	recursion_limit = GLOBAL_CONFIG['recursion_limit']
	log.info(f'Changing the recursion limit from {sys.getrecursionlimit()} to {recursion_limit} at the user\'s request.')
	sys.setrecursionlimit(recursion_limit)

####################################################################################################

def get_path_in_output_directory(short_file_path: str, subdirectory: Optional[str] = None) -> str:
	""" Gets the absolute path of a file inside the output directory relative to the working directory. """
	if subdirectory:
		short_file_path = os.path.join(subdirectory, short_file_path)
	path = os.path.join(GLOBAL_CONFIG['output_directory_path'], short_file_path) 
	return os.path.abspath(path)

def find_output_csv_files(prefix: str) -> list:
	""" Finds the paths to any CSV files inside the output directory by looking at their prefix. """
	csv_path = os.path.join(GLOBAL_CONFIG['output_directory_path'], fr'{prefix}*-*')
	csv_path = os.path.abspath(csv_path)
	csv_file_list = glob.glob(csv_path)
	csv_file_list = sorted(csv_file_list)
	return csv_file_list

def create_output_subdirectory(subdirectory: str) -> str:
	""" Creates a subdirectory in the output directory. """
	path = os.path.join(GLOBAL_CONFIG['output_directory_path'], subdirectory)
	path = os.path.abspath(path)
	os.makedirs(path, exist_ok=True)
	return path

def format_unix_timestamp(timestamp: str) -> Optional[str]:
	""" Formats a Unix timestamp using the format "YYYY-MM-DD hh:mm:ss". """

	result: Optional[str]

	try:
		result = datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
	except Exception as error:
		result = None
		log.error(f'Failed to format the timestamp "{timestamp}" with the error: {repr(error)}')

	return result

def change_datetime_string_format(datetime_string: str, source_format: str, destination_format: str, desired_locale: str) -> str:
	""" Changes the format of a datetime string. """

	previous_locale = locale.getlocale(locale.LC_TIME)
	locale.setlocale(locale.LC_TIME, desired_locale)
	
	datetime_string = datetime.strptime(datetime_string, source_format).strftime(destination_format)
	locale.setlocale(locale.LC_TIME, previous_locale)

	return datetime_string

def serialize_json_container(container: Union[list, dict]) -> Optional[str]:
	""" Serializes a list or dictionary as a JSON object. """

	return json.dumps(container) if container else None

def deserialize_json_container(container_str: Optional[str], default: Any = None) -> Optional[Union[list, dict]]:
	""" Deserializes a JSON object to a list or dictionary. """

	return json.loads(container_str) if pd.notna(container_str) else default # type: ignore[arg-type]

def has_file_extension(file_path: str, file_extension: str) -> bool:
	""" Checks if a file path ends with a given file extension. """

	return file_path.lower().endswith('.' + file_extension)

def replace_in_filename(file_path: str, old: str, new: str, remove_extra_extensions: bool = False) -> str:
	""" Replaces a substring in a path's filename. Any additional file extensions may be optionally removed.
	For example, if remove_extra_extensions is True: "path/old-file.txt.gz" -> "path/new-file.txt". """

	directory_path, filename = os.path.split(file_path)
	filename = filename.replace(old, new)

	if remove_extra_extensions:
		split_filename = filename.split('.')
		filename = '.'.join(split_filename[0:2])

	return os.path.join(directory_path, filename)

def join_and_normalize_paths(*component_list) -> str:
	""" Joins and normalizes one or more components into a single path. """

	joined_paths = os.path.join(*component_list)
	return os.path.normpath(joined_paths)

def delete_file(file_path: str) -> bool:
	""" Deletes a file, whether it exists or not. """
	
	try:
		os.remove(file_path)
		success = True
	except OSError:
		success = False

	return success

def delete_directory(directory_path: str) -> bool:
	""" Deletes a directory and its contents, whether it exists or not. """
	
	try:
		shutil.rmtree(directory_path)
		success = True
	except OSError:
		success = False

	return success

def append_dataframe_to_csv(df: pd.DataFrame, csv_path: str) -> None:
	""" Creates or appends a dataframe to a CSV file depending on whether it already exists. """
	add_header = not os.path.exists(csv_path)
	df.to_csv(csv_path, mode='a', header=add_header, index=False)

def append_file_to_csv(file_path: str, csv_path: str, **kwargs) -> None:
	""" Creates or appends a file to another CSV file depending on whether it already exists. """
	df = pd.read_csv(file_path, dtype=str, **kwargs)
	append_dataframe_to_csv(df, csv_path)

def check_range_overlap(range_1: List[int], range_2: List[int]) -> bool:
	""" Checks whether two integer ranges overlap. Each range is either a list or tuple with two elements that represent
	the beginning and ending points respectively. This second value cannot be smaller than the first one."""

	"""
		# E.g. A function defined from lines 10 to 20 and two Git diffs that show changes from lines 5 to 9, and from 19 to 21.
		# - A) 5 <= 20 and 10 <= 9 = True and False = False
		# - B) 19 <= 20 and 10 <= 21 = True and True = True
	"""

	if range_1[0] > range_1[1]:
		log.warning(f'The first range number is greater than the second in {range_1} (1).')
		return False

	if range_2[0] > range_2[1]:
		log.warning(f'The first range number is greater than the second in {range_2} (2).')
		return False

	return range_1[0] <= range_2[1] and range_2[0] <= range_1[1]

def lists_have_elements_in_common(a: list, b: list) -> bool:
	""" Checks if two lists have at least one element in common. """
	return len( set(a).intersection(set(b)) ) > 0

NUMERIC_REGEX = re.compile(r'\d+')

def extract_numeric(string: str, pattern: Optional[str] = None, convert: bool = False, all: bool = False) -> Optional[Union[int, str, list]]:
	""" Extracts zero or more numeric values from a string. """

	result = None
	regex = NUMERIC_REGEX if pattern is None else re.compile(pattern)	

	result = regex.findall(string)
	if convert:
		result = [int(match) for match in result]

	if not all:
		result = result[0] if result else None

	return result

def get_list_index_or_default(my_list: list, value: Any, default: Any = None) -> Any:
	""" Retrieves the index of a given item or a default value if it doesn't exist. """
	try:
		return my_list.index(value)
	except ValueError:
		return default

def remove_list_duplicates(my_list: list) -> list:
	""" Removes any duplicated values from a list. """
	return list(dict.fromkeys(my_list))

def dict_list_cartesian_product(**kwargs) -> list:
	""" Given a dictionary whose values are lists, creates a list with every possible dictionary combination and regular unpacked values.
	Adapted from the Propheticus function in propheticus.shared.Utils.cartesianProductDictionaryLists. """
	keys, values = zip(*kwargs.items())
	return [dict(zip(keys, prod)) for prod in itertools.product(*values)]

####################################################################################################

if __name__ == '__main__':
	pass