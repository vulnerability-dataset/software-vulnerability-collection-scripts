#!/usr/bin/env python3

"""
	This script converts any previously merged raw datasets to a specific version that can be parsed by the Propheticus tool.
	For each processed dataset, three files are created: *.info.txt, *.headers.txt, and *.data.txt.

	Before running this script, the raw datasets must be merged using "merge_raw_datasets.py".
"""

import json
import os

import pandas as pd # type: ignore

from modules.common import log, find_output_csv_files, replace_in_filename

####################################################################################################

for input_csv_path in find_output_csv_files('raw-dataset-merged'):

	_, _, _, unit_kind, _ = os.path.basename(input_csv_path).split('-', 4)

	log.info(f'Generating the Propheticus version of the raw {unit_kind} dataset using the information in "{input_csv_path}".')

	dataset = pd.read_csv(input_csv_path, dtype=str)

	"""
		We need to create the following text files. Taken from: https://eden.dei.uc.pt/~josep/EDCC2021/
		1. Info (suffix .info.txt): contains the number of samples per dataset;
		2. Headers (suffix: .headers.txt): contains a JSON object with all the features of the dataset, and its data type;
		3. Data (suffix: .data.txt): contains the samples separated by a space.

		Each sample contains:
		1. A description of the file instance;
		2. All the 54 software metrics;
		3. All the 228 alert types reported by Cppcheck;
		4. All the 123 alert types reported by Flawfinder;
		5. A label indicating if the files is non-vulnerable (0) or vulnerable (value > 0).

		Regarding the label in the multiclass dataset:
		- 0 represents non-vulnerable;
		- 1 represents vulnerable without an assigned category;
		- 2 represents memory management, followed by the remaining categories of Table 1 of the paper.

		Note that our raw datasets includes three class labels: binary, multiclass, and grouped multiclass.
	"""

	columns_to_remove = [	'ID_File', 'ID_Function', 'ID_Class', 'P_ID', 'FilePath',
							'Patched', 'Occurrence', 'Affected', 'R_ID', 'Visibility',
							'Complement', 'BeginLine', 'EndLine', 'NameMethod', 'NameClass',
							'COMMIT_HASH', 'COMMIT_DATE', 'COMMIT_YEAR', 'VULNERABILITY_CVE',
							'VULNERABILITY_YEAR', 'VULNERABILITY_CWE', 'VULNERABILITY_CATEGORY',
							'ELIGIBLE_FOR_ALERTS', 'COMMIT_HAS_ALERTS', 'TOTAL_ALERTS',
							'multiclass_label']

	dataset.drop(columns=columns_to_remove, errors='ignore', inplace=True)
	
	output_path_template = replace_in_filename(input_csv_path, 'raw-dataset-merged', 'propheticus-dataset')
	output_info_path = replace_in_filename(output_path_template, '.csv', '.info.txt')
	output_headers_path = replace_in_filename(output_path_template, '.csv', '.headers.txt')
	output_data_path = replace_in_filename(output_path_template, '.csv', '.data.txt')

	with open(output_info_path, 'w') as info_file:
		num_samples = str(len(dataset))
		info_file.write(num_samples)

	column_types = {'Description': 'string', 'RatioCommentToCode': 'float64'}
	headers = [{'name': column, 'type': column_types.get(column, 'int64')} for column in dataset.columns]

	with open(output_headers_path, 'w') as headers_file:
		json_headers = json.dumps(headers, indent=4)
		headers_file.write(json_headers)

	dataset.to_csv(output_data_path, sep=' ', header=False, index=False)

	log.info(f'Built the Propheticus {unit_kind} dataset to "{output_data_path}" successfully (including the info and header files).')

##################################################

log.info('Finished running.')
print('Finished running.')