#!/usr/bin/env python3

"""
	Plots the performance metrics generated after rerunning the best Propheticus configurations using temporal
	sliding windows. For each configuration, the following two files are created: 1) a text file containing part
	of a Latex table with the performance metrics; 2) an image containing nine lines (for three metrics and window
	sizes).

	Before running this script, the temporal window results must be generated using "validate_datasets_using_temporal_windows.py".
"""

import itertools
from typing import cast, Union

import matplotlib.pyplot as plt # type: ignore
import pandas as pd # type: ignore
from matplotlib.ticker import AutoMinorLocator, MultipleLocator # type: ignore

from modules.common import log, deserialize_json_container, find_output_csv_files, get_path_in_output_directory

####################################################################################################

for input_csv_path in find_output_csv_files('temporal-validation'):

	log.info(f'Plotting figures using the results in "{input_csv_path}".')

	results = pd.read_csv(input_csv_path)
	results.sort_values(['Index', 'Window Size', 'Testing Year'], inplace=True)

	results.insert(0, 'Precision', None)
	results.insert(0, 'Recall', None)
	results.insert(0, 'F1-Score', None)

	for index, row in results.iterrows():

		if row['Target Label'] == 'binary_label':

			confusion_matrix = cast(dict, deserialize_json_container(row['Confusion Matrix']))

			# True Label / Predicted Label
			tn = confusion_matrix['N']['N']
			tp = confusion_matrix['V(NC)']['V(NC)']
			fp = confusion_matrix['N']['V(NC)']
			fn = confusion_matrix['V(NC)']['N']

			precision = tp / (tp + fp)
			recall = tp / (tp + fn)

			results.at[index, 'Precision'] = precision
			results.at[index, 'Recall'] = recall
			results.at[index, 'F1-Score'] = 2 * (precision * recall) / (precision + recall)

	grouped_configs = results.groupby(by=['Index'])
	for index, config_df in grouped_configs:

		figure, axis = plt.subplots()
		colors = itertools.cycle(['firebrick', 'green', 'mediumblue', 'darkorange', 'aquamarine', 'blueviolet', 'gold', 'teal', 'hotpink'])

		grouped_windows = config_df.groupby(by=['Window Size', 'Target Label'])
		for (window_size, target_label), window_df in grouped_windows:

			window_size_label = f'{window_size} Years' if window_size != 'Variable' else window_size
			METRIC_COLUMNS = ['Precision', 'Recall', 'F1-Score'] if target_label == 'binary_label' else ['Precision (Weighted Avg)', 'Recall (Weighted Avg)', 'F1-Score (Weighted Avg)']
			
			for column_name in METRIC_COLUMNS:

				split_name = column_name.split(maxsplit=1)
				metric_label = split_name[0] if split_name else column_name
				x_data = window_df['Testing Year'].tolist()
				y_data = window_df[column_name].tolist()

				axis.plot(x_data, y_data, label=f'{metric_label} ({window_size_label})', color=next(colors))
		
		axis.set(xlabel=f'Testing Year', ylabel='Performance Metric', title=f'Configuration {index} Results Per Window Size')
		axis.legend(ncol=3, fontsize=8)

		axis.yaxis.set_major_locator(MultipleLocator(0.1))
		axis.yaxis.set_minor_locator(AutoMinorLocator(4))

		axis.set_ylim(top=1)

		figure.tight_layout()

		output_png_path = get_path_in_output_directory(f'c{index}-tw.png', 'validation')
		figure.savefig(output_png_path)

		output_pdf_path = get_path_in_output_directory(f'c{index}-tw.pdf', 'validation')
		figure.savefig(output_pdf_path)

		"""
		\begin{table}[ht]
			\centering
			\scalebox{1.0}
			{
				\begin{tabular}{|c|c|c|c|c|c|c|}
				\hline
				\thead{Window} & \thead{Training} & \thead{Testing} & \thead{Training \%} & \thead{Precision} & \thead{Recall} & \thead{F-score} \\
				\hline

				Variable & 2002-2018 & 2019 & 96\% & 0.9022 & 0.4771 & 0.5887 \\
				[...]

				\hline

				5 & 2014-2018 & 2019 & 95\% & 0.9035 & 0.4719 & 0.5835 \\
				[...]

				\hline

				10 & 2009-2018 & 2019 & 96\% & 0.9027 & 0.4638 & 0.5756 \\
				[...]

				\hline
				\end{tabular}
			}
			\caption{The best results for configuration $C_1$ using the three temporal sliding windows.}
			\label{tab:ml-results-temporal-c1}
		\end{table}
		"""

		table_text = 'Window Size,Training Years,Testing Year,Training Samples,Training Percentage,Precision,Recall,F1-Score\n'
		for _, row in config_df.iterrows():

			window_size = row['Window Size']
			training_years = cast(Union[list, str], deserialize_json_container(row['Training Years']))
			testing_year = row['Testing Year']
			training_samples = row['Training Samples']
			training_percentage = round(row['Training Percentage'] * 100)
			
			if row['Target Label'] == 'binary_label':
				precision = row['Precision']
				recall = row['Recall']
				f_score = row['F1-Score']
			else:
				precision = row['Precision (Weighted Avg)']
				recall = row['Recall (Weighted Avg)']
				f_score = row['F1-Score (Weighted Avg)']

			training_years = str(training_years[0]) + '-' + str(training_years[-1])

			table_text += f'{window_size} & {training_years} & {testing_year} & {training_samples} & {training_percentage}\\% & {precision:.4f} & {recall:.4f} & {f_score:.4f} \\\\\n'

		output_table_path = get_path_in_output_directory(f'c{index}-tw.txt', 'validation')
		with open(output_table_path, 'w', encoding='utf-8') as file:
			file.write(table_text)

		log.info(f'Saved the plot for configuration {index} to "{output_png_path}" and "{output_pdf_path}".')

log.info('Finished running.')
print('Finished running.')