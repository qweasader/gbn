# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882203");
  script_version("2023-07-11T05:06:07+0000");
  script_cve_id("CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709",
                "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301",
                "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307",
                "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412",
                "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025",
                "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598",
                "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602",
                "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605", "CVE-2006-7243");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2015-06-24 06:15:52 +0200 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for php CESA-2015:1135 centos7");
  script_tag(name:"summary", value:"Check the version of php");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language
  commonly used with the Apache HTTP Server.

A flaw was found in the way the PHP module for the Apache httpd web server
handled pipelined requests. A remote attacker could use this flaw to
trigger the execution of a PHP script in a deinitialized interpreter,
causing it to crash or, possibly, execute arbitrary code. (CVE-2015-3330)

A flaw was found in the way PHP parsed multipart HTTP POST requests. A
specially crafted request could cause PHP to use an excessive amount of CPU
time. (CVE-2015-4024)

An uninitialized pointer use flaw was found in PHP's Exif extension. A
specially crafted JPEG or TIFF file could cause a PHP application using the
exif_read_data() function to crash or, possibly, execute arbitrary code
with the privileges of the user running that PHP application.
(CVE-2015-0232)

An integer overflow flaw leading to a heap-based buffer overflow was found
in the way PHP's FTP extension parsed file listing FTP server responses. A
malicious FTP server could use this flaw to cause a PHP application to
crash or, possibly, execute arbitrary code. (CVE-2015-4022)

Multiple flaws were discovered in the way PHP performed object
unserialization. Specially crafted input processed by the unserialize()
function could cause a PHP application to crash or, possibly, execute
arbitrary code. (CVE-2014-8142, CVE-2015-0231, CVE-2015-0273,
CVE-2015-2787, CVE-2015-4147, CVE-2015-4148, CVE-2015-4599, CVE-2015-4600,
CVE-2015-4601, CVE-2015-4602, CVE-2015-4603)

It was found that certain PHP functions did not properly handle file names
containing a NULL character. A remote attacker could possibly use this flaw
to make a PHP script access unexpected files and bypass intended file
system access restrictions. (CVE-2015-2348, CVE-2015-4025, CVE-2015-4026,
CVE-2015-3411, CVE-2015-3412, CVE-2015-4598)

Multiple flaws were found in the way the way PHP's Phar extension parsed
Phar archives. A specially crafted archive could cause PHP to crash or,
possibly, execute arbitrary code when opened. (CVE-2015-2301,
CVE-2015-2783, CVE-2015-3307, CVE-2015-3329, CVE-2015-4021)

Multiple flaws were found in PHP's File Information (fileinfo) extension.
A remote attacker could cause a PHP application to crash if it used
fileinfo to identify type of attacker supplied files. (CVE-2014-9652,
CVE-2015-4604, CVE-2015-4605)

A heap buffer overflow flaw was found in the enchant_broker_request_dict()
function of PHP's enchant extension. An attacker able to make a PHP
application enchant dictionaries could possibly cause it to crash.
(CVE-2014-9705)

A buffer over-read flaw was found in the GD library us ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"php on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1135");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-June/021191.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.4.16~36.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
