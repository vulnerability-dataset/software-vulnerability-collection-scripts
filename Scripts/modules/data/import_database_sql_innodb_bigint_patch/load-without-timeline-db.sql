CREATE DATABASE  IF NOT EXISTS `software` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `software`;

SET SQL_SAFE_UPDATES = 0;
SET FOREIGN_KEY_CHECKS = 0;

SELECT NOW() as '  ', 'Creating Database!' as '  ' FROM DUAL;

source ./scripts/01-crebas.sql
source ./scripts/02-MFSA.sql
source ./scripts/03-A-insert_modules.sql
source ./scripts/03-Repositories.sql
source ./scripts/04-kernel_vulnerabilities.sql
source ./scripts/05-kernel_patches.sql
source ./scripts/06-kernel_source.sql
source ./scripts/07-mozilla_vulnerabilities.sql
source ./scripts/08-mozilla_patches.sql
source ./scripts/09-mozilla_source.sql
source ./scripts/10-glibc_vulnerabilities.sql
source ./scripts/11-glibc_patches.sql
source ./scripts/12-glibc_source.sql
source ./scripts/13-xen-vulnerabilities.sql
source ./scripts/14-xen-patches.sql
source ./scripts/15-xen_functions.sql
source ./scripts/16-vulnerabilities_httpd.sql
source ./scripts/17-patches_httpd.sql
source ./scripts/17-XSAs.sql
source ./scripts/18-source_httpd.sql
source ./scripts/19-codeheader_git.sql
source ./scripts/20-codeheader_httpdsvn.sql
source ./scripts/21-time_commits.sql
source ./scripts/22-update_classification-2005.sql
source ./scripts/23-update_classification_2010-2014.sql
source ./scripts/24-updateClassification2009.sql
source ./scripts/25-releases_glibc.sql

SELECT NOW() as '  ', 'Starting Observations' as '  ' FROM DUAL;

source ./scripts/observations/observacoes_caio.sql
source ./scripts/observations/observacoes_eduarda.sql
source ./scripts/observations/observacoes_felipe.sql
source ./scripts/observations/observacoes_henrique.sql
source ./scripts/observations/observacoes_joao.sql
source ./scripts/observations/observacoes_jose.sql
source ./scripts/observations/observacoes_marcos.sql
source ./scripts/observations/observacoes_gabriel.sql

SELECT NOW() as '  ', 'DB created. Starting dumps: HTTPD' as '  ' FROM DUAL;

source ./scripts/httpd/0-drop-tables-4.sql
source ./scripts/httpd/1-create-tables-4.sql
source ./scripts/httpd/20151125-dump-CLASSES_4_apache-mysql.sql
source ./scripts/httpd/20151125-dump-FILES_4_apache-mysql.sql
source ./scripts/httpd/20151125-dump-FUNCTIONS_4_apache-mysql.sql
source ./scripts/httpd/30-primary-keys-4.sql
source ./scripts/httpd/32-foreigh-keys-4.sql

SELECT NOW() as '  ', 'DB created. Starting dumps: Glibc' as '  ' FROM DUAL;

source ./scripts/glibc/0-drop-tables-5.sql
source ./scripts/glibc/1-create-tables-5.sql
source ./scripts/glibc/20151125-dump-CLASSES_5_glibc-mysql.sql
source ./scripts/glibc/20151125-dump-FILES_5_glibc-mysql.sql
source ./scripts/glibc/20151125-dump-FUNCTIONS_5_glibc-mysql.sql
source ./scripts/glibc/30-primary-keys-5.sql
source ./scripts/glibc/32-foreigh-keys-5.sql

SELECT NOW() as '  ', 'DB created. Starting dumps: XEN' as '  ' FROM DUAL;

source ./scripts/xen/0-drop-tables-3.sql
source ./scripts/xen/1-create-tables-3.sql
source ./scripts/xen/20151125-dump-CLASSES_3_arch-mysql.sql
source ./scripts/xen/20151125-dump-CLASSES_3_tools-mysql.sql
source ./scripts/xen/20151125-dump-CLASSES_3_xen-mysql.sql
source ./scripts/xen/20151125-dump-FILES_3_arch-mysql.sql
source ./scripts/xen/20151125-dump-FILES_3_tools-mysql.sql
source ./scripts/xen/20151125-dump-FILES_3_xen-mysql.sql
source ./scripts/xen/20151125-dump-FUNCTIONS_3_arch-mysql.sql
source ./scripts/xen/20151125-dump-FUNCTIONS_3_tools-mysql.sql
source ./scripts/xen/20151125-dump-FUNCTIONS_3_xen-mysql.sql
source ./scripts/xen/30-primary-keys-3.sql
source ./scripts/xen/32-foreigh-keys-3.sql

SELECT NOW() as '  ', 'DB created. Starting dumps: KERNEL' as '  ' FROM DUAL;

source ./scripts/kernel/0-drop-tables-2.sql
source ./scripts/kernel/1-create-tables-2.sql
source ./scripts/kernel/20151125-dump-CLASSES_2_arch-mysql.sql
source ./scripts/kernel/20151125-dump-CLASSES_2_driver_extra-mysql.sql
source ./scripts/kernel/20151125-dump-CLASSES_2_fs-mysql.sql
source ./scripts/kernel/20151125-dump-CLASSES_2_kernel-mysql.sql
source ./scripts/kernel/20151125-dump-CLASSES_2_linux-mysql.sql
source ./scripts/kernel/20151125-dump-CLASSES_2_net-mysql.sql
source ./scripts/kernel/20151125-dump-FILES_2_arch-mysql.sql
source ./scripts/kernel/20151125-dump-FILES_2_driver_extra-mysql.sql
source ./scripts/kernel/20151125-dump-FILES_2_fs-mysql.sql
source ./scripts/kernel/20151125-dump-FILES_2_kernel-mysql.sql
source ./scripts/kernel/20151125-dump-FILES_2_linux-mysql.sql
source ./scripts/kernel/20151125-dump-FILES_2_net-mysql.sql
source ./scripts/kernel/20151125-dump-FUNCTIONS_2_arch-mysql.sql
source ./scripts/kernel/20151125-dump-FUNCTIONS_2_driver_extra-mysql.sql
source ./scripts/kernel/20151125-dump-FUNCTIONS_2_fs-mysql.sql
source ./scripts/kernel/20151125-dump-FUNCTIONS_2_kernel-mysql.sql
source ./scripts/kernel/20151125-dump-FUNCTIONS_2_linux-mysql.sql
source ./scripts/kernel/20151125-dump-FUNCTIONS_2_net-mysql.sql
source ./scripts/kernel/30-primary-keys-2.sql
source ./scripts/kernel/32-foreigh-keys-2.sql

SELECT NOW() as '  ', 'DB created. Starting dumps: MOZILLA' as '  ' FROM DUAL;

source ./scripts/mozilla/0-drop-tables-1.sql
source ./scripts/mozilla/1-create-tables-1.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_dom-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_javascript_extras-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_javascript-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_javascript_xpconnect-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_layout_rendering-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_libraries-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_mozilla-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_network-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_toolkit-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_webpage_structure-mysql.sql
source ./scripts/mozilla/20151125-dump-CLASSES_1_widget-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_dom-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_javascript_extras-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_javascript-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_javascript_xpconnect-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_layout_rendering-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_libraries-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_mozilla-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_network-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_toolkit-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_webpage_structure-mysql.sql
source ./scripts/mozilla/20151125-dump-FILES_1_widget-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_dom-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_javascript_extras-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_javascript-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_javascript_xpconnect-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_layout_rendering-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_libraries-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_mozilla-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_network-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_toolkit-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_webpage_structure-mysql.sql
source ./scripts/mozilla/20151125-dump-FUNCTIONS_1_widget-mysql.sql
source ./scripts/mozilla/30-primary-keys-1.sql
source ./scripts/mozilla/32-foreigh-keys-1.sql

SELECT NOW() as '  ', 'Generate news metrics for files and PKs' as '  ' FROM DUAL;

source ./scripts/26-metricsfiles.sql
source ./scripts/27-foreigh_keys.sql
source ./scripts/28-update_date_httpd.sql
source ./scripts/29-update_cves.sql
source ./scripts/31-update_releases_subversion_httpd.sql

SELECT NOW() as '  ', 'Data from TOMCAT and DERBY' as '  ' FROM DUAL;

source ./scripts/32-table_tomcat_patches.sql
source ./scripts/33-table_tomcat_vulnerabilities.sql
source ./scripts/34-observations_tomcat.sql
source ./scripts/35-table_derby_patches.sql
source ./scripts/36-table_derby_vulnerabilities.sql
source ./scripts/37-codeheader_derby.sql
source ./scripts/38-codeheader_tomcat.sql
source ./scripts/39-modules_tomcat_derby.sql

SELECT NOW() as '  ', 'DB created. Starting dumps: TOMCAT' as '  ' FROM DUAL;

source ./scripts/tomcat/0-drop-tables-6.sql
source ./scripts/tomcat/1-create-tables-6.sql
source ./scripts/tomcat/20151125-dump-CLASSES_6_tomcat-mysql.sql
source ./scripts/tomcat/20151125-dump-FILES_6_tomcat-mysql.sql
source ./scripts/tomcat/20151125-dump-FUNCTIONS_6_tomcat-mysql.sql
source ./scripts/tomcat/30-primary-keys-6.sql
source ./scripts/tomcat/32-foreigh-keys-6.sql


SELECT NOW() as '  ', 'DB created. Starting dumps: DERBY' as '  ' FROM DUAL;

source ./scripts/derby/0-drop-tables-7.sql
source ./scripts/derby/1-create-tables-7.sql
source ./scripts/derby/20151125-dump-CLASSES_7_derby-mysql.sql
source ./scripts/derby/20151125-dump-FILES_7_derby-mysql.sql
source ./scripts/derby/20151125-dump-FUNCTIONS_7_derby-mysql.sql
source ./scripts/derby/30-primary-keys-7.sql
source ./scripts/derby/32-foreigh-keys-7.sql

SELECT NOW() as '  ', 'New Metrics...' as '  ' FROM DUAL;

source ./scripts/40-metrics_files_tomcat_derby.sql

SELECT NOW() as '  ', 'Update classes and files patches' as '  ' FROM DUAL;

source ./scripts/80-update_classes_and_files_patched.sql

SELECT NOW() as '  ', 'Create affected column' as '  ' FROM DUAL;

source ./scripts/affected/create_affected_column.sql

SELECT NOW() as '  ', 'Create viewes and indexes' as '  ' FROM DUAL;

source ./scripts/81-viewes.sql
source ./scripts/82-create-indexes.sql

SELECT NOW() as '  ', 'Process Finished' as '  ' FROM DUAL;

SET SQL_SAFE_UPDATES = 1;
SET FOREIGN_KEY_CHECKS = 1;
