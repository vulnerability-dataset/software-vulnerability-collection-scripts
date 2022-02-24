#!/usr/bin/env python3

"""
	Validates any merged raw datasets by rerunning the best Propheticus configurations with a new data partitioning
	strategy: use a range of vulnerability years as the training subset, and the next year as the testing subset.
	For example: (2008-2012, 2013), (2009-2013, 2014), ..., (2014-2018, 2019) for a window size of 5.

	Only the following machine learning techniques are supported:
	- Classification Algorithms: Random Forests, Bagging, Extreme Gradient Boosting (XGBoost).
	- Dimensionality Reduction: Variance.
	- Data Balancing: RandomUnderSampler, RandomOverSampler.

	Before running this script, the raw datasets must be merged using "merge_raw_datasets.py" and the best classifier
	parameter configurations must be determined using Propheticus.
"""

import os
import re
from hashlib import sha256
from typing import Any, Union

import matplotlib.pyplot as plt # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore
from imblearn.under_sampling import RandomUnderSampler # type: ignore
from imblearn.over_sampling import RandomOverSampler # type: ignore
from sklearn import __version__ as sklearn_version, metrics # type: ignore
from sklearn.ensemble import BaggingClassifier, RandomForestClassifier # type: ignore
from sklearn.feature_selection import VarianceThreshold # type: ignore
from xgboost import XGBClassifier

from modules.common import log, GLOBAL_CONFIG, create_output_subdirectory, find_output_csv_files, replace_in_filename, serialize_json_container

####################################################################################################

log.info(f'Using scikit-learn version {sklearn_version}.')

ML_PARAMS = GLOBAL_CONFIG['temporal_window']
num_runs = ML_PARAMS['num_runs']

# Create an abbreviated name for each class.
prediction_classes: Union[list, dict]
prediction_classes = ['Neutral', 'Vulnerable (No Category)'] + list(GLOBAL_CONFIG['vulnerability_categories'].keys()) + ['Vulnerable (With Category)']
prediction_classes = [re.sub(r'[a-z ]', '', class_) for class_ in prediction_classes]
prediction_classes = {value: name for value, name in enumerate(prediction_classes)}

label_values = list(prediction_classes.keys())
label_names = list(prediction_classes.values())

output_directory_path = create_output_subdirectory('validation')

for code_unit, allowed in GLOBAL_CONFIG['allowed_code_units'].items():

	if not allowed:
		log.info(f'Skipping the merged {code_unit} dataset at the user\'s request.')
		continue

	for input_csv_path in find_output_csv_files(f'raw-dataset-merged-{code_unit}'):

		log.info(f'Validating the dataset in "{input_csv_path}" using a temporal window.')
		output_csv_path = replace_in_filename(input_csv_path, 'raw-dataset-merged', 'temporal-validation', remove_extra_extensions=True)

		dataset_hash: Any = sha256()
		with open(input_csv_path, 'rb') as file:
			dataset_hash.update(file.read())
		dataset_hash = dataset_hash.hexdigest()

		dataset = pd.read_csv(input_csv_path)
		
		# Some values in these columns may be empty (NAN) by mistake, so we'll remove them
		# and make sure to convert the vulnerability year from a float to an integer.
		dataset.dropna(subset=['VULNERABILITY_YEAR', 'COMMIT_DATE'], inplace=True)
		dataset['VULNERABILITY_YEAR'] = dataset['VULNERABILITY_YEAR'].astype(np.int64)

		columns_to_remove = [	'ID_File', 'ID_Function', 'ID_Class', 'P_ID', 'FilePath',
								'Patched', 'Occurrence', 'Affected', 'R_ID', 'Visibility',
								'Complement', 'BeginLine', 'EndLine', 'NameMethod', 'NameClass',
								'COMMIT_HASH', 'COMMIT_YEAR', 'VULNERABILITY_CVE',
								'VULNERABILITY_CWE', 'VULNERABILITY_CATEGORY', 'ELIGIBLE_FOR_ALERTS',
								'COMMIT_HAS_ALERTS', 'TOTAL_ALERTS', 'multiclass_label']

		dataset.drop(columns=columns_to_remove, errors='ignore', inplace=True)
		dataset.sort_values(['VULNERABILITY_YEAR', 'COMMIT_DATE'], inplace=True)
		
		year_count = dataset['VULNERABILITY_YEAR'].value_counts()
		year_ratio = dataset['VULNERABILITY_YEAR'].value_counts(normalize=True)
		log.info(f'The vulnerability year count is: {year_count.to_dict()}')
		log.info(f'The vulnerability year ratio is: {year_ratio.to_dict()}')

		year_list = sorted(dataset['VULNERABILITY_YEAR'].unique().tolist())
		
		average_metric_list = [f'{metric.title()} ({average.title()})' for metric in ['precision', 'recall', 'f1-score'] for average in ['micro avg', 'macro avg', 'weighted avg']]

		results = pd.DataFrame(columns=['Experiment', 'Window Size', 'Training Years', 'Testing Year',
										'Training Samples', 'Training Percentage', 'Testing Samples', 'Testing Percentage',
										'Index', 'Name', 'Runs', 'Algorithm', 'Target Label',
										'Data Balancing', 'Algorithm Parameters', 'Dimensionality Reduction',
										'Confusion Matrix', 'Accuracy'] + average_metric_list)

		for window_size in ML_PARAMS['data_split']['window_size']:

			window_size_name = window_size if window_size is not None else 'Variable'
			begin_test_year = ML_PARAMS['data_split']['begin_test_year']

			if window_size is None:
				# E.g. (2002-2012, 2013), (2002-2013, 2014), ..., (2002-2018, 2019).
				window_list = [(year_list[:i+1], next_year) for i, (year, next_year) in enumerate(zip(year_list, year_list[1:])) if next_year >= begin_test_year]
			else:
				# E.g. (2008-2012, 2013), (2009-2013, 2014), ..., (2014-2018, 2019) for a window size of 5.
				window_list = [(year_list[i-window_size:i], year) for i, year in enumerate(year_list) if year >= begin_test_year]
			
			window_list.reverse()

			for w, (train_years, test_year) in enumerate(window_list):

				if window_size is None:

					is_test = dataset['VULNERABILITY_YEAR'] == test_year
					num_test = is_test.sum()
					
					# Fix the number of testing samples at a given percentage (if possible) and use the rest for training.
					test_ratio = ML_PARAMS['data_split']['variable_window_test_ratio']
					expected_num_train = min(round(num_test * (1 - test_ratio) / test_ratio), len(dataset))
					
					is_previous_year = dataset['VULNERABILITY_YEAR'] < test_year
					is_train = dataset[is_previous_year].tail(expected_num_train).index
					
					assert len(is_train) <= expected_num_train, f'Expected no more than {expected_num_train} training samples, got {len(is_train)}.'
					num_train = len(is_train) 

					train_years = sorted(dataset.loc[is_train, 'VULNERABILITY_YEAR'].unique().tolist())

				else:
					is_train = dataset['VULNERABILITY_YEAR'].isin(train_years)
					is_test = dataset['VULNERABILITY_YEAR'] == test_year

					num_train = is_train.sum()
					num_test = is_test.sum()

				# Note that there is a third subset of the data that may not be used since it falls outside the year range.
				train_ratio = num_train / (num_train + num_test)
				test_ratio = num_test / (num_train + num_test)
				
				log.info(f'Using temporal window {w+1} of {len(window_list)} ({window_size_name}): Train({train_years}) with {num_train} samples ({train_ratio}) and Test({test_year}) with {num_test} samples ({test_ratio}).')

				default_algorithm_parameters = ML_PARAMS['default_algorithm_parameters']
				configuration_list = ML_PARAMS['configurations']

				for c, configuration in enumerate(configuration_list):

					name = configuration['name']
					log.info(f'Training and testing using the configuration {c+1} of {len(configuration_list)}: "{name}".')
					print(f'Window {w+1} of {len(window_list)} ({window_size_name}) - Configuration {c+1} of {len(configuration_list)}:')

					target_label = configuration['target_label']
					dimensionality_reduction = configuration['dimensionality_reduction']
					data_balancing = configuration['data_balancing']
					classification_algorithm = configuration['classification_algorithm']
					algorithm_parameters = configuration['algorithm_parameters']

					default_parameters = default_algorithm_parameters.get(classification_algorithm, {})
					for key, value in default_parameters.items():
						if key not in algorithm_parameters:
							algorithm_parameters[key] = value

					# This identifier should include the test ratio since the same window ranges can use different train/test splits.
					experiment_params = (dataset_hash, train_years, test_year, num_test, f'{test_ratio:.4f}', target_label, dimensionality_reduction, data_balancing, classification_algorithm, algorithm_parameters)

					experiment_hash: Any = sha256()
					for param in experiment_params:
						experiment_hash.update(str(param).encode())
					experiment_hash = experiment_hash.hexdigest()

					confusion_matrix_file_path = os.path.join(output_directory_path, f'{experiment_hash}_cm.png')

					if os.path.isfile(confusion_matrix_file_path):
						log.info(f'Skipping configuration {c+1} with the hash "{experiment_hash}" since it was already executed.')
						print(f'- Skipping configuration "{experiment_hash}" since it was already executed.')
						continue

					real_label_values = sorted(dataset[target_label].unique().tolist())
					real_label_names = [label_names[label] for label in real_label_values]
					excluded_column_list = ['Description', 'COMMIT_DATE', 'VULNERABILITY_YEAR'] + GLOBAL_CONFIG['target_labels']
					
					y_test = dataset.loc[is_test, target_label]
					total_y_pred = np.empty(shape=(0, 0), dtype=y_test.dtype)
					total_y_test = np.empty(shape=(0, 0), dtype=y_test.dtype)

					critical_error = False

					for r in range(num_runs):

						log.info(f'Executing run {r+1} of {num_runs} for configuration {c+1}.')
						print(f'-> Run {r+1} of {num_runs}...')

						X_train = dataset.loc[is_train, :].drop(columns=excluded_column_list)
						X_test = dataset.loc[is_test, :].drop(columns=excluded_column_list)
						y_train = dataset.loc[is_train, target_label]

						for method in dimensionality_reduction:

							if method == 'variance':

								# Specified in "propheticus/preprocessing/variance.py".
								VARIANCE_THRESHOLD = 0.0

								original_columns = X_train.columns

								selector = VarianceThreshold(VARIANCE_THRESHOLD)
								selector.fit(X_train)
								selected_indexes = selector.get_support(indices=True)

								X_train = X_train[X_train.columns[selected_indexes]]
								X_test = X_test[X_test.columns[selected_indexes]]

								removed_indexes = np.setdiff1d(np.arange(len(original_columns)), selected_indexes)
								removed_features = original_columns[removed_indexes]

								log.info(f'Removed the following {len(removed_features)} features with a variance less or equal to {VARIANCE_THRESHOLD}: {removed_features}')
							else:
								log.critical(f'Skipping configuration due to the unsupported "{method}" dimensionality reduction technique.')
								critical_error = True
								break

						if critical_error:
							break

						for method in data_balancing:

							train_label_count = y_train.value_counts().to_dict()

							if method == 'RandomUnderSampler':

								log.info(f'Label count before undersampling: {train_label_count}')

								majority_label = max(train_label_count, key=lambda x: train_label_count[x])
								second_majority_label = max(train_label_count, key=lambda x: train_label_count[x] if x != majority_label else -1)
								second_majority_count = train_label_count[second_majority_label]

								# Specified in "propheticus/configs/Sampling.py".
								UNDERSAMPLING_MAJORITY_TO_MINORITY_RATIO = 1.0
								# See buildDataBalancingTransformers() in "propheticus/core/DatasetReduction.py".
								desired_label_count = {}
								for label, count in train_label_count.items():
									desired_label_count[label] = int(second_majority_count * UNDERSAMPLING_MAJORITY_TO_MINORITY_RATIO) if label == majority_label else count

								log.info(f'Label count after undersampling: {desired_label_count}')
								
								sampler = RandomUnderSampler(sampling_strategy=desired_label_count)

							elif method == 'RandomOverSampler':

								log.info(f'Label count before oversampling: {train_label_count}')

								majority_label = max(train_label_count, key=lambda x: train_label_count[x])

								# Specified in "propheticus/configs/Sampling.py".
								OVERSAMPLING_RATIO = 3.0
								# See buildDataBalancingTransformers() in "propheticus/core/DatasetReduction.py".
								desired_label_count = {}
								for label, count in train_label_count.items():
									desired_label_count[label] = int(count * OVERSAMPLING_RATIO) if label != majority_label else count

								log.info(f'Label count after oversampling: {desired_label_count}')

								sampler = RandomOverSampler(sampling_strategy=desired_label_count)

							else:
								log.critical(f'Skipping configuration due to the unsupported "{method}" sampling technique.')
								critical_error = True
								break

							X_train, y_train = sampler.fit_resample(X_train, y_train)

						if critical_error:
							break

						# See "propheticus/configs/Classification.py".
						if classification_algorithm == 'random_forests':
							classifier = RandomForestClassifier(**algorithm_parameters)
						elif classification_algorithm == 'bagging':
							classifier = BaggingClassifier(**algorithm_parameters)
						elif classification_algorithm == 'xgboost':
							classifier = XGBClassifier(**algorithm_parameters)
						else:
							log.critical(f'Skipping configuration due to the unsupported "{classification_algorithm}" classification algorithm.')
							break
				
						classifier.fit(X_train, y_train)
						y_pred = classifier.predict(X_test)

						total_y_test = np.append(total_y_test, y_test)
						total_y_pred = np.append(total_y_pred, y_pred)

					##################################################

					if critical_error:
						continue

					confusion_matrix = metrics.confusion_matrix(total_y_test, total_y_pred, labels=real_label_values)
					confusion_matrix_display = metrics.ConfusionMatrixDisplay(confusion_matrix, display_labels=real_label_names)
					confusion_matrix_display.plot()
					
					axis = plt.gca()
					figure = plt.gcf()
					
					train_year_range = str(train_years[0]) + ' to ' + str(train_years[-1])
					axis.set(title=f'Configuration {c+1}: Window({window_size_name}), Train({train_year_range}), Test({test_year})')
					
					figure.savefig(confusion_matrix_file_path)

					confusion_matrix_dict: dict = {}
					for i, row_values in enumerate(confusion_matrix):
						true_label = real_label_names[i]
						confusion_matrix_dict[true_label] = {}
						for j, value in enumerate(row_values):
							pred_label = real_label_names[j]
							confusion_matrix_dict[true_label][pred_label] = int(value)

					report = metrics.classification_report(total_y_test, total_y_pred, target_names=real_label_names, output_dict=True)
					accuracy = report['accuracy']

					row = {
						'Experiment': experiment_hash,
						'Window Size': window_size_name,
						'Training Years': serialize_json_container(train_years),
						'Testing Year': test_year,
						'Training Samples': num_train,
						'Training Percentage': f'{train_ratio:.4f}',
						'Testing Samples': num_test,
						'Testing Percentage': f'{test_ratio:.4f}',
						'Index': c+1,
						'Name': name,
						'Runs': num_runs,
						'Algorithm': classification_algorithm,
						'Target Label': target_label,
						'Data Balancing': data_balancing,
						'Algorithm Parameters': algorithm_parameters,
						'Dimensionality Reduction': dimensionality_reduction,
						'Confusion Matrix': serialize_json_container(confusion_matrix_dict),
						'Accuracy': f'{accuracy:.4f}',
					}

					for average in ['micro avg', 'macro avg', 'weighted avg']:
						for metric in ['precision', 'recall', 'f1-score']:
							column_name = f'{metric.title()} ({average.title()})'
							average_metric = report.get(average, {}).get(metric)
							row[column_name] = f'{average_metric:.4f}' if average_metric is not None else average_metric

					results = results.append(row, ignore_index=True)
					results.to_csv(output_csv_path, index=False)

##################################################

log.info('Finished running.')
print('Finished running.')