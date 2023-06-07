# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120247");
  script_cve_id("CVE-2013-6712", "CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3515", "CVE-2014-3981", "CVE-2014-4049");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:18 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-05T14:03:08+0000");
  script_tag(name:"last_modification", value:"2022-01-05 14:03:08 +0000 (Wed, 05 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-393");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-393.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the ALAS-2014-393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the way the File Information (fileinfo) extension parsed certain Composite Document Format (CDF) files. A remote attacker could use this flaw to crash a PHP application using fileinfo via a specially crafted CDF file.

acinclude.m4, as used in the configure script in PHP 5.5.13 and earlier, allows local users to overwrite arbitrary files via a symlink attack on the /tmp/phpglibccheck file.

A buffer over-read flaw was found in the way the DateInterval class parsed interval specifications. An attacker able to make a PHP application parse a specially crafted specification using DateInterval could possibly cause the PHP interpreter to crash.

A heap-based buffer overflow flaw was found in the way PHP parsed DNS TXT records. A malicious DNS server or a man-in-the-middle attacker could possibly use this flaw to execute arbitrary code as the PHP interpreter if a PHP application used the dns_get_record() function to perform a DNS query.

A type confusion issue was found in the SPL ArrayObject and SPLObjectStorage classes' unserialize() method. A remote attacker able to submit specially crafted input to a PHP application, which would then unserialize this input using one of the aforementioned methods, could use this flaw to execute arbitrary code with the privileges of the user running that PHP application.");

  script_tag(name:"affected", value:"'php' package(s) on Amazon Linux.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mssql", rpm:"php-mssql~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.3.29~1.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
