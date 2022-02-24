#!/usr/bin/env python3

"""
	This script adds two indexes to the PATCHES and ALERT tables in the database.

	Before running this script, the security alerts table must be created using "create_alert_and_cwe_tables_in_database.py".
"""

from mysql.connector.errorcode import ER_DUP_KEYNAME # type: ignore

from modules.common import log
from modules.database import Database

####################################################################################################

def create_indexes_in_database() -> None:

	with Database() as db:

		log.info('Adding the (P_COMMIT) index to the PATCHES table')
		success, error_code = db.execute_query('CREATE INDEX IDX_PATCHES_P_COMMIT ON PATCHES (P_COMMIT);')

		if not success and error_code != ER_DUP_KEYNAME:
			log.error(f'Failed to add the index to the PATCHES table with the error code {error_code}.')
			return

		log.info('Adding the (R_ID, P_COMMIT, P_OCCURRENCE) index to the ALERT table')
		success, error_code = db.execute_query('CREATE INDEX IDX_ALERT_R_ID_P_COMMIT_P_OCCURRENCE ON ALERT (R_ID, P_COMMIT, P_OCCURRENCE);')

		if not success and error_code != ER_DUP_KEYNAME:
			log.error(f'Failed to add the index to the ALERT table with the error code {error_code}.')
			return

		##################################################

		log.info('Committing changes.')
		db.commit()

create_indexes_in_database()

log.info('Finished running.')
print('Finished running.')
