#!/usr/bin/env python3

"""
	This module defines any methods and classes that are used to download and parse vulnerability metadata from websites.
"""

import random
import re
import time
from typing import Optional, Pattern, Union
from urllib.parse import urlsplit, parse_qsl

import requests

from .common import log, GLOBAL_CONFIG

####################################################################################################

class ScrapingManager():
	""" Represents a connection to one or more websites and provides methods for downloading their pages. """

	session: requests.Session
	connect_timeout: float
	read_timeout: float
	
	use_random_headers: bool
	sleep_random_amounts: bool

	DEFAULT_HEADERS: dict = {
		'Accept-Language': 'en-US',
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
	}

	BROWSER_HEADERS: list = list( GLOBAL_CONFIG['http_headers'].values() )

	def __init__(	self, url_prefixes: Union[str, list] = [],
					connect_timeout: float = 10.0, read_timeout: float = 5.0,
					max_retries: int = 5, headers: dict = DEFAULT_HEADERS,
					use_random_headers: bool = True,sleep_random_amounts: bool = True):
		
		session = requests.Session()
		adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
	
		if isinstance(url_prefixes, str):
			url_prefixes = [url_prefixes]

		for prefix in url_prefixes:
			session.mount(prefix, adapter)

		session.headers.update(headers)
		
		self.session = session
		self.connect_timeout = connect_timeout
		self.read_timeout = read_timeout
		self.use_random_headers = use_random_headers
		self.sleep_random_amounts = sleep_random_amounts

	def download_page(self, url: str, params: Optional[dict] = None) -> Optional[requests.Response]:
		""" Downloads a web page givens its URL and query parameters. """

		response: Optional[requests.Response]

		try:

			if self.use_random_headers:
				headers = random.choice(ScrapingManager.BROWSER_HEADERS)
				self.session.headers.update(headers)
			
			if self.sleep_random_amounts:
				sleep_amount = random.uniform(1.0, 3.0)
				time.sleep(sleep_amount)

			response = self.session.get(url, params=params, timeout=(self.connect_timeout, self.read_timeout))
			response.raise_for_status()
		except Exception as error:
			response = None
			log.error(f'Failed to download the page "{url}" with the error: {repr(error)}')
		
		return response

####################################################################################################

class ScrapingRegex():
	""" Represents various constants used to parse key information from any relevant websites. """

	PAGE_TITLE: Pattern = re.compile(r'Go to page \d+', re.IGNORECASE)
	CVE: Pattern = re.compile(r'(CVE-\d+-\d+)', re.IGNORECASE)

	# BUG TRACKERS
	BUGZILLA_URL: Pattern = re.compile(r'https?://.*bugzilla.*', re.IGNORECASE)

	"""
	Examples:
	- Mozilla: https://bugzilla.mozilla.org/show_bug.cgi?id=1580506
	- Apache: https://bz.apache.org/bugzilla/show_bug.cgi?id=57531
	- Glibc: https://sourceware.org/bugzilla/show_bug.cgi?id=24114
	"""

	# SECURITY ADVISORIES
	MFSA_URL: Pattern = re.compile(r'https?://.*mozilla.*security.*mfsa.*', re.IGNORECASE)
	MFSA_ID: Pattern = re.compile(r'(mfsa\d+-\d+)', re.IGNORECASE)

	XSA_URL: Pattern = re.compile(r'https?://.*xen.*xsa.*advisory.*', re.IGNORECASE)
	XSA_ID: Pattern = re.compile(r'advisory-(\d+)', re.IGNORECASE)

	APACHE_SECURITY_URL: Pattern = re.compile(r'https?://.*apache.*security.*vulnerabilities.*', re.IGNORECASE)
	APACHE_SECURITY_ID: Pattern = re.compile(r'vulnerabilities_(\d+)', re.IGNORECASE)

	"""
	Examples:
	- Mozilla: https://www.mozilla.org/security/advisories/mfsa2019-31/
	- Mozilla: http://www.mozilla.org/security/announce/mfsa2005-58.html 
	- Xen: https://xenbits.xen.org/xsa/advisory-300.html
	- Apache: https://httpd.apache.org/security/vulnerabilities_24.html
	"""

	# VERSION CONTROL
	GIT_URL: Pattern = re.compile(r'https?://.*git.*commit.*', re.IGNORECASE)
	GITHUB_URL: Pattern = re.compile(r'https?://.*github\.com.*commit.*', re.IGNORECASE)
	SVN_URL: Pattern = re.compile(r'https?://.*svn.*rev.*', re.IGNORECASE)

	GIT_COMMIT_HASH_LENGTH = 40
	GIT_COMMIT_HASH: Pattern = re.compile(r'([A-Fa-f0-9]{40})', re.IGNORECASE)
	SVN_REVISION_NUMBER: Pattern = re.compile(r'(\d+)', re.IGNORECASE)

	"""
	Examples:
	- Linux: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eff73de2b1600ad8230692f00bc0ab49b166512a
	- Glibc: https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9

	- Linux: https://github.com/torvalds/linux/commit/6ef36ab967c71690ebe7e5ef997a8be4da3bc844
	- Apache: https://github.com/apache/httpd/commit/e427c41257957b57036d5a549b260b6185d1dd73 

	- Apache: http://svn.apache.org/viewcvs?rev=292949&view=rev
	"""

	GIT_DIFF_LINE_NUMBERS: Pattern = re.compile(r'^@@ -(?P<from_begin>\d+)(,(?P<from_total>\d+))? \+(?P<to_begin>\d+)(,(?P<to_total>\d+))? @@.*')
	# Example: "@@ -424,20 +420,0 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,"

####################################################################################################

if __name__ == '__main__':
	pass