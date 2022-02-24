#!/usr/bin/env python3

"""
	This script splits a CSV file into multiple ones.
"""

from argparse import ArgumentParser
from math import ceil

import pandas as pd # type: ignore

from modules.common import log, replace_in_filename

####################################################################################################

parser = ArgumentParser(description='Split a single CSV file into multiple ones.')

parser.add_argument('input_csv_path', help='The path to the CSV file.')
parser.add_argument('num_csv_files', type=int, choices=range(2,100), help='The number of files to create.')
parser.add_argument('filename_prefix', help='The prefix where the partition number (1 to num_csv_files) will be added.')

args = parser.parse_args()

log.info(f'Spliting the CSV in "{args.input_csv_path}" into {args.num_csv_files} files.')

csv_data = pd.read_csv(args.input_csv_path, dtype=str)
num_rows = len(csv_data)
del csv_data

if num_rows >= args.num_csv_files:

	chunk_size = ceil(num_rows / args.num_csv_files)
	csv_chunks = pd.read_csv(args.input_csv_path, dtype=str, chunksize=chunk_size)

	for i, chunk in enumerate(csv_chunks):
		output_csv_path = replace_in_filename(args.input_csv_path, args.filename_prefix, f'{args.filename_prefix}-{i+1}-of-{args.num_csv_files}-parts')
		chunk.to_csv(output_csv_path, index=False)
		log.info(f'Split {len(chunk)} rows ({chunk.index[0]} to {chunk.index[-1]}) into "{output_csv_path}".')

	result = f'Finished running. Split {num_rows} rows into {args.num_csv_files} files.'
	log.info(result)
	print(result)

else:
	result = f'Cannot split {num_rows} rows into {args.num_csv_files} files.'
	log.error(result)
	print(result)