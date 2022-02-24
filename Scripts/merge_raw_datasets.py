#!/usr/bin/env python3

"""
	This script merges any previously generated raw datasets into a single one for each code unit type.

	Before running this script, the raw datasets must be created using "build_raw_dataset_from_database.py".
"""

import os

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, append_file_to_csv, delete_file, find_output_csv_files, replace_in_filename

####################################################################################################

for code_unit, allowed in GLOBAL_CONFIG['allowed_code_units'].items():

	if not allowed:
		log.info(f'Skipping the {code_unit} raw dataset at the user\'s request.')
		continue

	dataset_file_list = find_output_csv_files(f'raw-dataset-{code_unit}')
	output_csv_path = replace_in_filename(dataset_file_list[0], 'raw-dataset', 'raw-dataset-merged', remove_extra_extensions=True)
	output_csv_path, _ = output_csv_path.rsplit('.', 1)
	output_csv_path += '.csv'

	print(output_csv_path)

	# So we don't accidentally merge the same datasets twice.
	if not os.path.isfile(output_csv_path):
		
		if not dataset_file_list:
			log.warning(f'Could not find any {code_unit} datasets to merge.')
			continue

		for i, input_csv_path in enumerate(dataset_file_list):
			log.info(f'Merging the raw {code_unit} datasets using the information in "{input_csv_path}".')
			append_file_to_csv(input_csv_path, output_csv_path)
		
	dataset = pd.read_csv(output_csv_path, dtype=str)
	dataset['multiclass_label'] = pd.to_numeric(dataset['multiclass_label'])

	# Balance the number of neutral samples by removing a given percentage.
	label_ratio = dataset['multiclass_label'].value_counts(normalize=True).to_dict()
	log.info(f'The multiclass label ratio is: {label_ratio}')

	is_neutral = dataset['multiclass_label'] == 0
	neutral_samples_to_remove = dataset[is_neutral].sample(frac=GLOBAL_CONFIG['dataset_neutral_sample_removal_ratio'])
	dataset.drop(neutral_samples_to_remove.index, inplace=True)

	# Group vulnerable categories under a certain threshold.
	dataset['grouped_multiclass_label'] = dataset['multiclass_label']
	label_threshold = GLOBAL_CONFIG['dataset_vulnerable_label_threshold']
	grouped_class_label = len(GLOBAL_CONFIG['vulnerability_categories']) + 2

	is_vulnerable = dataset['multiclass_label'] >= 1
	vulnerable_label_count = dataset[is_vulnerable]['multiclass_label'].value_counts()
	vulnerable_label_ratio = dataset[is_vulnerable]['multiclass_label'].value_counts(normalize=True)
	log.info(f'The vulnerable multiclass label count is: {vulnerable_label_count.to_dict()}')
	log.info(f'The vulnerable multiclass label ratio is: {vulnerable_label_ratio.to_dict()}')

	for label, ratio in vulnerable_label_ratio.items():

		# The vulnerable (no category) label should not be grouped.
		if label <= 1:
			continue

		if ratio < label_threshold:
			has_label = dataset['multiclass_label'] == label
			dataset.loc[has_label, 'grouped_multiclass_label'] = grouped_class_label
			log.info(f'Grouped the label {label} since its ratio {ratio} falls under the threshold {label_threshold}.')

	grouped_label_count = dataset['grouped_multiclass_label'].value_counts()
	grouped_label_ratio = dataset['grouped_multiclass_label'].value_counts(normalize=True)
	log.info(f'The grouped multiclass label count is: {grouped_label_count.to_dict()}')
	log.info(f'The grouped multiclass label ratio is: {grouped_label_ratio.to_dict()}')

	dataset.to_csv(output_csv_path, index=False)
	log.info(f'Merged the raw datasets to "{output_csv_path}" successfully.')

##################################################

log.info('Finished running.')
print('Finished running.')