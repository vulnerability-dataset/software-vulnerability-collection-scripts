#!/usr/bin/env python3

"""
	This module defines a class that represents a software vulnerability and that contains methods for scraping its data from the CVE Details website.
"""

import re
from typing import TYPE_CHECKING, Callable, Optional
from urllib.parse import urlsplit, parse_qsl

if TYPE_CHECKING:
	from .project import Project

import bs4 # type: ignore

from .common import log, remove_list_duplicates, serialize_json_container
from .scraping import ScrapingManager, ScrapingRegex

####################################################################################################

class Cve:
	""" Represents a vulnerability (CVE) scraped from the CVE Details website. """

	CVE_DETAILS_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.cvedetails.com')

	id: str
	url: str
	project: 'Project'

	publish_date: Optional[str]
	last_update_date: Optional[str]

	cvss_score: 				Optional[str]
	confidentiality_impact: 	Optional[str]
	integrity_impact: 			Optional[str]
	availability_impact: 		Optional[str]
	access_complexity: 			Optional[str]
	authentication: 			Optional[str]
	gained_access: 				Optional[str]
	vulnerability_types: 		Optional[list]
	cwe: 						Optional[str]

	affected_products: dict

	bugzilla_urls: list
	bugzilla_ids: list
	advisory_urls: list
	advisory_ids: list

	advisory_info: dict

	git_urls: list
	git_commit_hashes: list
	svn_urls: list
	svn_revision_numbers: list

	def __init__(self, id: str, project: 'Project'):
		self.id = id
		self.url = f'https://www.cvedetails.com/cve/{self.id}'
		self.project = project

		self.cve_details_soup = None

		self.publish_date = None
		self.last_update_date = None

		self.cvss_score = None
		self.confidentiality_impact = None
		self.integrity_impact = None
		self.availability_impact = None
		self.access_complexity = None
		self.authentication = None
		self.gained_access = None
		self.vulnerability_types = None
		self.cwe = None

		self.affected_products = {}

		self.bugzilla_urls = []
		self.bugzilla_ids = []
		self.advisory_urls = []
		self.advisory_ids = []

		self.advisory_info = {}

		self.git_urls = []
		self.git_commit_hashes = []
		self.svn_urls = []
		self.svn_revision_numbers = []

	def __str__(self):
		return self.id

	def download_cve_details_page(self) -> bool:
		""" Downloads the CVE's page from the CVE Details website. """

		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(self.url)
		if response is not None:
			self.cve_details_soup = bs4.BeautifulSoup(response.text, 'html.parser')
		
		return response is not None

	def scrape_dates_from_page(self):
		""" Scrapes any date values from the CVE's page. """

		"""
		<div class="cvedetailssummary">
			Memory safety bugs were reported in Firefox 57 and Firefox ESR 52.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Thunderbird &lt; 52.6, Firefox ESR &lt; 52.6, and Firefox &lt; 58.	<br>
			<span class="datenote">Publish Date : 2018-06-11	Last Update Date : 2018-08-03</span>
		</div>
		"""

		dates_span = self.cve_details_soup.find('span', class_='datenote')
		if dates_span is None:
			log.warning(f'--> No dates span found for {self}.')

		dates_text = dates_span.get_text(strip=True)
		
		cve_dates = {}
		for date in re.split(r'\t+', dates_text):
			key, value = date.split(' : ')
			cve_dates[key] = value

		self.publish_date = cve_dates.get('Publish Date')
		self.last_update_date = cve_dates.get('Last Update Date')

	def scrape_basic_attributes_from_page(self):
		""" Scrapes any basic attributes from the CVE's page. """

		"""
		<table id="cvssscorestable" class="details">
			<tbody>
				<tr>
					<th>CVSS Score</th>
					<td><div class="cvssbox" style="background-color:#ff9c20">7.5</div></td>
				</tr>
				<tr>
					<th>Confidentiality Impact</th>
					<td><span style="color:orange">Partial</span>
					<span class="cvssdesc">(There is considerable informational disclosure.)</span></td>
				</tr>
				<tr>
					<th>Access Complexity</th>
					<td><span style="color:red">Low</span>
					<span class="cvssdesc">(Specialized access conditions or extenuating circumstances do not exist. Very little knowledge or skill is required to exploit. )</span></td>
				</tr>
				<tr>
					<th>Authentication</th>
					<td><span style="color:red">Not required</span>
					<span class="cvssdesc">(Authentication is not required to exploit the vulnerability.)</span></td>
				</tr>
				<tr>
					<th>Gained Access</th>
					<td><span style="color:green;">None</span></td>
				</tr>
				<tr>
					<th>Vulnerability Type(s)</th>
					<td><span class="vt_overflow">Overflow</span><span class="vt_memc">Memory corruption</span></td>
				</tr>
				<tr>
					<th>CWE ID</th>
					<td><a href="//www.cvedetails.com/cwe-details/119/cwe.html" title="CWE-119 - CWE definition">119</a></td>
				</tr>
			</tbody>
		</table>
		"""

		scores_table = self.cve_details_soup.find('table', id='cvssscorestable')
		if scores_table is None:
			log.warning(f'--> No scores table found for {self}.')
			return

		scores_th_list = scores_table.find_all('th')
		scores_td_list = scores_table.find_all('td')

		cve_attributes = {}
		for th, td in zip(scores_th_list, scores_td_list):

			key = th.get_text(strip=True)
			value = None

			if key == 'Vulnerability Type(s)':
				value = [span.get_text(strip=True) for span in td.find_all('span')]
			else:
				span = td.find('span')
				if span is not None:
					value = span.get_text(strip=True)
				else:
					value = td.get_text(strip=True)
			
			cve_attributes[key] = value

		self.cvss_score 			= cve_attributes.get('CVSS Score')
		self.confidentiality_impact = cve_attributes.get('Confidentiality Impact')
		self.integrity_impact 		= cve_attributes.get('Integrity Impact')
		self.availability_impact 	= cve_attributes.get('Availability Impact')
		self.access_complexity 		= cve_attributes.get('Access Complexity')
		self.authentication 		= cve_attributes.get('Authentication')
		self.gained_access 			= cve_attributes.get('Gained Access')
		self.vulnerability_types 	= cve_attributes.get('Vulnerability Type(s)')

		cwe = cve_attributes.get('CWE ID')
		if cwe is not None and not cwe.isnumeric():
			cwe = None
		self.cwe = cwe

	def scrape_affected_product_versions_from_page(self):
		""" Scrapes any affected products and their versions from the CVE's page. """

		"""
		<table class="listtable" id="vulnprodstable">
			<tbody>
				<tr>
					<th class="num">#</th>
					<th>Product Type</th>
					<th>Vendor</th>
					<th>Product</th>
					<th>Version</th>
					<th>Update</th>
					<th>Edition</th>
					<th>Language</th>
					<th></th>
				</tr>
				<tr>
					<td class="num">1</td>
					<td>Application </td>
					<td><a href="//www.cvedetails.com/vendor/452/Mozilla.html" title="Details for Mozilla">Mozilla</a></td>
					<td><a href="//www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452" title="Product Details Mozilla Firefox">Firefox</a></td>
					<td></td>
					<td></td>
					<td></td>
					<td></td>
					<td><a href="/version/12613/Mozilla-Firefox-.html" title="Mozilla Firefox ">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-452/product_id-3264/version_id-12613/Mozilla-Firefox-.html" title="Vulnerabilities of Mozilla Firefox ">Vulnerabilities</a></td>
				</tr>
				<tr>
					<td class="num">2 </td>
					<td>Application </td>
					<td><a href="//www.cvedetails.com/vendor/44/Netscape.html" title="Details for Netscape">Netscape</a></td>
					<td><a href="//www.cvedetails.com/product/64/Netscape-Navigator.html?vendor_id=44" title="Product Details Netscape Navigator">Navigator</a></td>
					<td>7.0.2 </td>
					<td></td>
					<td></td>
					<td></td>
					<td><a href="/version/11359/Netscape-Navigator-7.0.2.html" title="Netscape Navigator 7.0.2">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-44/product_id-64/version_id-11359/Netscape-Navigator-7.0.2.html" title="Vulnerabilities of Netscape Navigator 7.0.2">Vulnerabilities</a></td>
				</tr>
			</tbody>
		</table>
		"""

		products_table = self.cve_details_soup.find('table', id='vulnprodstable')
		if products_table is None:
			log.warning(f'--> No products table found for {self}.')
			return

		# Parse each row in the product table.
		th_list = products_table.find_all('th')
		th_list = [th.get_text(strip=True) for th in th_list]
		column_indexes = {	'vendor': 	th_list.index('Vendor'),
							'product': 	th_list.index('Product'),
							'version': 	th_list.index('Version')}

		tr_list = products_table.find_all('tr')
		for tr in tr_list:

			# Skip the header row.
			if tr.find('th'):
				continue

			td_list = tr.find_all('td')

			def get_column_value_and_url(name):
				""" Gets a specific cell value and any URL it references from the current row given its column name.. """

				idx = column_indexes[name]
				td = td_list[idx]

				value = td.get_text(strip=True)
				url = td.find('a', href=True)

				if value in ['', '-']:
					value = None

				if url is not None:
					url = url['href']

				return value, url

			_, vendor_url  = get_column_value_and_url('vendor')
			product, product_url = get_column_value_and_url('product')
			version, _ = get_column_value_and_url('version')

			vendor_pattern = f'/{self.project.vendor_id}/'
			product_pattern = f'/{self.project.product_id}/' if self.project.product_id is not None else ''
			
			# Check if the vendor and product belong to the current project.
			if vendor_pattern in vendor_url and product_pattern in product_url:

				if product not in self.affected_products:
					self.affected_products[product] = []
				
				if version is not None and version not in self.affected_products[product]:
					self.affected_products[product].append(version)

	def scrape_references_from_page(self):
		""" Scrapes any references and links from the CVE's page. """

		"""
		<table class="listtable" id="vulnrefstable">
			<tbody>
				<tr>
					<td class="r_average">
						<a href="https://github.com/torvalds/linux/commit/09ccfd238e5a0e670d8178cf50180ea81ae09ae1" target="_blank" title="External url">https://github.com/torvalds/linux/commit/09ccfd238e5a0e670d8178cf50180ea81ae09ae1</a>
						CONFIRM
						<br>
					</td>
				</tr>
				<tr>
					<td class="r_average">
						<a href="https://bugzilla.redhat.com/show_bug.cgi?id=1292045" target="_blank" title="External url">https://bugzilla.redhat.com/show_bug.cgi?id=1292045</a>
						CONFIRM
						<br>
					</td>
				</tr>
			</tbody>
		</table>
		"""

		references_table = self.cve_details_soup.find('table', id='vulnrefstable')
		if references_table is None:
			log.warning(f'--> No references table found for {self}.')
			return

		def list_all_urls(url_regex: str, url_handler: Callable = None):
			""" Creates a list of URL that match a regex (or a list of regexes). If a handler method is passed as the second argument, then it
			will be called for each URL in order to create and return a secondary list. This may be used to extract specific parts of the URL."""

			a_list = references_table.find_all('a', href=url_regex)
			
			url_list = []
			for a in a_list:
				url = a['href']
				if re.search(self.project.url_pattern, url, re.IGNORECASE):
					url_list.append(url)

			secondary_list = []
			if url_handler is not None:
				for url in url_list:
					secondary_value = url_handler(url)
					if secondary_value is not None:
						secondary_list.append(secondary_value)

			return url_list, secondary_list

		def get_query_param(url: str, query_key_list: list) -> Optional[str]:
			""" Gets the value of the first parameter in a URL's query segment given a list of keys to check. """

			split_url = urlsplit(url)
			params = dict(parse_qsl(split_url.query))
			result = None
			
			for query_key in query_key_list:
				result = params.get(query_key)
				if result is not None:
					break

			return result

		"""
			Various helper methods to handle specific URLs from different sources.
		"""

		def handle_bugzilla_urls(url: str) -> Optional[str]:
			id = get_query_param(url, ['id', 'bug_id'])
			
			if id is None:
				log.error(f'--> Could not find a valid Bugzilla ID in "{url}".')

			return id

		def handle_advisory_urls(url: str) -> Optional[str]:
			split_url = urlsplit(url)
			id = None

			for regex in [ScrapingRegex.MFSA_ID, ScrapingRegex.XSA_ID, ScrapingRegex.APACHE_SECURITY_ID]:
				match = regex.search(split_url.path)
				if match is not None:
					id = match.group(1)

					if regex is ScrapingRegex.MFSA_ID:
						id = id.upper()
						id = id.replace('MFSA', 'MFSA-')
					elif regex is ScrapingRegex.XSA_ID:
						id = 'XSA-' + id
					elif regex is ScrapingRegex.APACHE_SECURITY_ID:
						id = 'APACHE-' + id[0] + '.' + id[1:]

					break

			if id is None:
				log.error(f'--> Could not find a valid advisory ID in "{url}".')

			return id

		def handle_git_urls(url: str) -> Optional[str]:
			commit_hash = get_query_param(url, ['id', 'h'])

			if commit_hash is None:
				split_url = urlsplit(url)
				path_components = split_url.path.rsplit('/')
				commit_hash = path_components[-1]

			# If the hash length is less than 40, we need to refer to the repository
			# to get the full hash.
			if commit_hash is not None and len(commit_hash) < ScrapingRegex.GIT_COMMIT_HASH_LENGTH:
				commit_hash = self.project.find_full_git_commit_hash(commit_hash)

			if commit_hash is not None and not ScrapingRegex.GIT_COMMIT_HASH.match(commit_hash):
				commit_hash = None
			
			if commit_hash is None:
				log.error(f'--> Could not find a valid commit hash in "{url}".')
			
			return commit_hash

		def handle_svn_urls(url: str) -> Optional[str]:
			revision_number = get_query_param(url, ['rev', 'revision', 'pathrev'])

			if revision_number is not None:

				# In some rare cases, the revision number can be prefixed with 'r'.
				# As such, we'll only extract the numeric part of this value.
				match = ScrapingRegex.SVN_REVISION_NUMBER.search(revision_number)
				if match is not None:
					# For most cases, this is the same value.
					revision_number = match.group(1)
				else:
					# For cases where the query parameter was not a valid number.
					revision_number = None

			if revision_number is None:
				log.error(f'--> Could not find a valid revision number in "{url}".')

			return revision_number

		self.bugzilla_urls, self.bugzilla_ids 		= list_all_urls(ScrapingRegex.BUGZILLA_URL, handle_bugzilla_urls)
		self.advisory_urls, self.advisory_ids 		= list_all_urls([ScrapingRegex.MFSA_URL, ScrapingRegex.XSA_URL, ScrapingRegex.APACHE_SECURITY_URL], handle_advisory_urls)

		self.git_urls, self.git_commit_hashes 		= list_all_urls([ScrapingRegex.GIT_URL, ScrapingRegex.GITHUB_URL], handle_git_urls)
		self.svn_urls, self.svn_revision_numbers 	= list_all_urls(ScrapingRegex.SVN_URL, handle_svn_urls)

	def remove_duplicated_values(self):
		""" Removes any duplicated values from specific CVE attributes that contain lists. """

		self.vulnerability_types 	= remove_list_duplicates(self.vulnerability_types)

		self.bugzilla_urls 			= remove_list_duplicates(self.bugzilla_urls)
		self.bugzilla_ids 			= remove_list_duplicates(self.bugzilla_ids)
		self.advisory_urls 			= remove_list_duplicates(self.advisory_urls)
		self.advisory_ids 			= remove_list_duplicates(self.advisory_ids)

		self.git_urls 				= remove_list_duplicates(self.git_urls)
		self.git_commit_hashes 		= remove_list_duplicates(self.git_commit_hashes)
		self.svn_urls 				= remove_list_duplicates(self.svn_urls)
		self.svn_revision_numbers 	= remove_list_duplicates(self.svn_revision_numbers)

	def serialize_containers(self):
		""" Serializes specific CVE attributes that contain lists or dictionaries using JSON. """

		self.vulnerability_types 	= serialize_json_container(self.vulnerability_types)

		self.affected_products 		= serialize_json_container(self.affected_products)

		self.bugzilla_urls 			= serialize_json_container(self.bugzilla_urls)
		self.bugzilla_ids 			= serialize_json_container(self.bugzilla_ids)
		self.advisory_urls 			= serialize_json_container(self.advisory_urls)
		self.advisory_ids 			= serialize_json_container(self.advisory_ids)

		self.advisory_info 			= serialize_json_container(self.advisory_info)

		self.git_urls 				= serialize_json_container(self.git_urls)
		self.git_commit_hashes 		= serialize_json_container(self.git_commit_hashes)
		self.svn_urls 				= serialize_json_container(self.svn_urls)
		self.svn_revision_numbers 	= serialize_json_container(self.svn_revision_numbers)

if __name__ == '__main__':
	pass