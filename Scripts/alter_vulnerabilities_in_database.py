#!/usr/bin/env python3

"""
	This script makes the following structural changes to the VULNERABILITIES table in the database:
	- Adds columns that represent each vulnerability's CWE (V_CWE) and project (R_ID).
	- Sets the values of the R_ID column and adds a foreign key relationship that references the projects in the REPOSITORIES_SAMPLE table.
	- Renames the V_ID primary key to V_ID_LEGACY and creates a new V_ID column containing numeric IDs with the AUTO_INCREMENT attribute.
	- This last process is also applied to the PATCHES table since it contains a foreign key to VULNERABILITIES.
"""

from mysql.connector.errorcode import ER_DUP_FIELDNAME, ER_FK_DUP_NAME # type: ignore

from modules.common import log
from modules.database import Database

####################################################################################################

def alter_vulnerabilities_in_database() -> None:

	with Database() as db:

		log.info('Adding the CWE column to the VULNERABILITIES table.')

		success, error_code = db.execute_query(	'''
												ALTER TABLE VULNERABILITIES
												ADD COLUMN V_CWE VARCHAR(10) DEFAULT 'TBD' AFTER CVE;
												''')

		if not success and error_code != ER_DUP_FIELDNAME:
			log.error(f'Failed to add the CWE column with the error code {error_code}.')
			return

		##################################################

		log.info('Adding the repository ID column to the VULNERABILITIES table.')

		success, error_code = db.execute_query(	'''
												ALTER TABLE VULNERABILITIES
												ADD COLUMN R_ID TINYINT NOT NULL AFTER V_ID;
												''')

		if not success and error_code != ER_DUP_FIELDNAME:
			log.error(f'Failed to add the repository ID column with the error code {error_code}.')
			return

		##################################################

		log.info('Setting the repository ID values based on the vulnerability IDs in the VULNERABILITIES table.')

		PREFIX_TO_ID = {'vuln': 1, 'ker': 2, 'xen': 3, 'httpd': 4, 'glibc': 5, 'tomcat': 6, 'derby': 7}

		for prefix, id in PREFIX_TO_ID.items():

			success, error_code = db.execute_query(	'''
													UPDATE VULNERABILITIES
													SET R_ID = %(id)s
													WHERE REGEXP_SUBSTR(V_ID, '^[a-z]+') = %(prefix)s;
													''',
													params={'id': id, 'prefix': prefix})

			if not success:
				log.error(f'Failed to set the repository ID for the prefix "{prefix}" ({id}) with the error code {error_code}.')
				return

		##################################################

		log.info('Adding the repository ID foreign key to the VULNERABILITIES table.')

		success, error_code = db.execute_query(	'''
												ALTER TABLE VULNERABILITIES
												ADD CONSTRAINT FK_VULNERABILITIES_REPOSITORIES_SAMPLE
												FOREIGN KEY (R_ID) REFERENCES REPOSITORIES_SAMPLE (R_ID);
												''')

		if not success and error_code != ER_FK_DUP_NAME:
			log.error(f'Failed to add the repository ID foreign key with the error code {error_code}.')
			return

		##################################################

		log.info('Changing the primary key in the VULNERABILITIES table.')

		success, error_code = db.execute_query(	'''
												ALTER TABLE VULNERABILITIES
												RENAME COLUMN V_ID TO V_ID_LEGACY,
												ADD COLUMN V_ID INTEGER AFTER V_ID_LEGACY;
												''')

		if not success:
			log.error(f'Failed to create the new vulnerability ID column with the error code {error_code}.')
			return

		success, error_code = db.execute_query(	'''
												ALTER TABLE VULNERABILITIES
												DROP PRIMARY KEY,
												ADD PRIMARY KEY (V_ID),
												MODIFY COLUMN V_ID INTEGER NOT NULL AUTO_INCREMENT,
												MODIFY COLUMN V_ID_LEGACY VARCHAR(30) NULL,
												MODIFY COLUMN VULNERABILITY_URL VARCHAR(3000);
												''')

		if not success:
			log.error(f'Failed to change the primary key with the error code {error_code}.')
			return

		##################################################

		log.info('Changing the foreign key in the PATCHES table.')

		success, error_code = db.execute_query(	'''
												ALTER TABLE PATCHES
												RENAME COLUMN V_ID TO V_ID_LEGACY,
												ADD COLUMN V_ID INTEGER NOT NULL AFTER V_ID_LEGACY;
												''')

		if not success:
			log.error(f'Failed to create the new vulnerability ID column with the error code {error_code}.')
			return

		success, error_code = db.execute_query(	'''
												UPDATE PATCHES AS P
												INNER JOIN VULNERABILITIES AS V ON P.V_ID_LEGACY = V.V_ID_LEGACY
												SET P.V_ID = V.V_ID;
												''')

		if not success:
			log.error(f'Failed to set the new vulnerability ID values with the error code {error_code}.')
			return

		success, error_code = db.execute_query(	'''
												ALTER TABLE PATCHES
												DROP INDEX FK_RESPECTIVE_VULNERABILITY,
												ADD CONSTRAINT FK_PATCHES_VULNERABILITIES
												FOREIGN KEY (V_ID) REFERENCES VULNERABILITIES (V_ID) ON DELETE RESTRICT ON UPDATE RESTRICT;
												''')

		if not success:
			log.error(f'Failed to change the foreign key with the error code {error_code}.')
			return

		##################################################

		log.info('Committing changes.')
		db.commit()

alter_vulnerabilities_in_database()

log.info('Finished running.')
print('Finished running.')
