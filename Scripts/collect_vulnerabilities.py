#!/usr/bin/env python3

"""
	This script collects any vulnerabilities associated with the five C/C++ projects by scraping the CVE Details website.
	
	This information includes the CVE identifier, publish date, CVSS score, various impacts, vulnerability types, the CWE ID, and
	the URLs to other relevant websites like a project's Bugzilla or Security Advisory platforms.

	For each project, this information is saved to a CSV file.
"""

import csv
import os

from modules.common import log
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:

	CSV_HEADER = [
		'CVE', 'CVE URL',
		
		'Publish Date', 'Last Update Date',

		'CVSS Score', 'Confidentiality Impact', 'Integrity Impact',
		'Availability Impact', 'Access Complexity', 'Authentication',
		'Gained Access', 'Vulnerability Types', 'CWE',
		
		'Affected Product Versions',

		'Bugzilla URLs', 'Bugzilla IDs',
		'Advisory URLs', 'Advisory IDs', 'Advisory Info',
		'Git URLs', 'Git Commit Hashes',
		'SVN URLs', 'SVN Revision Numbers'
	]
	
	project.create_output_subdirectory()

	output_csv_path = project.get_base_output_csv_path('cve')

	with open(output_csv_path, 'w', newline='') as csv_file:

		csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADER)
		csv_writer.writeheader()

		for cve in project.scrape_vulnerabilities_from_cve_details():

			cve.serialize_containers()
			
			csv_row = {
				'CVE': cve.id, 'CVE URL': cve.url,

				'Publish Date': cve.publish_date, 'Last Update Date': cve.last_update_date,

				'CVSS Score': cve.cvss_score, 'Confidentiality Impact': cve.confidentiality_impact, 'Integrity Impact': cve.integrity_impact,
				'Availability Impact': cve.availability_impact, 'Access Complexity': cve.access_complexity, 'Authentication': cve.authentication,
				'Gained Access': cve.gained_access, 'Vulnerability Types': cve.vulnerability_types, 'CWE': cve.cwe,

				'Affected Product Versions': cve.affected_products,

				'Bugzilla URLs': cve.bugzilla_urls, 'Bugzilla IDs': cve.bugzilla_ids,
				'Advisory URLs': cve.advisory_urls, 'Advisory IDs': cve.advisory_ids, 'Advisory Info': cve.advisory_info,
				'Git URLs': cve.git_urls, 'Git Commit Hashes': cve.git_commit_hashes,
				'SVN URLs': cve.svn_urls, 'SVN Revision Numbers': cve.svn_revision_numbers
			}

			csv_writer.writerow(csv_row)

	log.info(f'Finished running for the project "{project}".')

log.info('Finished running.')
print('Finished running.')
