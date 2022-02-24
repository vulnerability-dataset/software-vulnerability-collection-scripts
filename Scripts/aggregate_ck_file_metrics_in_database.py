#!/usr/bin/env python3

"""
	This script updates the CK file metric columns (DIT, NOC, CBC, RFC, CBO, LCOM) in the FILES_* tables by summing the values in each
	file's corresponding rows in the CLASSES_* tables.

	Before running this script, the file and class metrics must be first inserted using "insert_metrics_in_database.py".
"""

from modules.common import log
from modules.database import Database
from modules.project import Project

####################################################################################################

def aggregate_ck_file_metrics_in_database() -> None:

	with Database() as db:

		project_list = Project.get_project_list_from_config()
		for project in project_list:
			
			file_metrics_table = 'FILES_' + str(project.database_id)
			class_metrics_table = 'CLASSES_' + str(project.database_id)

			log.info(f'Aggregating the CK file metrics for the project "{project}".')

			success, error_code = db.execute_query(	f'''
														UPDATE {file_metrics_table} F
														LEFT JOIN
														(
															SELECT
																ID_File,
																SUM(MaxInheritanceTree) AS SumMaxInheritanceTree, 	SUM(CountClassDerived) 		AS SumCountClassDerived,
														        SUM(CountClassBase) 	AS SumCountClassBase, 		SUM(CountDeclMethodAll) 	AS SumCountDeclMethodAll,
														        SUM(CountClassCoupled) 	AS SumCountClassCoupled, 	SUM(PercentLackOfCohesion) 	AS SumPercentLackOfCohesion
															FROM {class_metrics_table}
															GROUP BY ID_File
														) C ON F.ID_File = C.ID_File
														SET
														DIT = IFNULL(SumMaxInheritanceTree, 0), 	NOC = IFNULL(SumCountClassDerived, 0),
														CBC = IFNULL(SumCountClassBase, 0), 		RFC = IFNULL(SumCountDeclMethodAll, 0),
														CBO = IFNULL(SumCountClassCoupled, 0), 		LCOM = IFNULL(SumPercentLackOfCohesion, 0)
														WHERE DIT IS NULL OR NOC IS NULL OR CBC IS NULL OR RFC IS NULL OR CBO IS NULL OR LCOM IS NULL;
													''')

			if not success:
				log.error(f'Failed to aggregate the CK metrics with the error code {error_code}.')
				return

			log.info(f'Updated {db.cursor.rowcount} rows in the table {file_metrics_table} for the project "{project}".')

		log.info('Committing changes.')
		db.commit()

##################################################

aggregate_ck_file_metrics_in_database()

log.info('Finished running.')
print('Finished running.')
