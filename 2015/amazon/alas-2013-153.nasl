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
  script_oid("1.3.6.1.4.1.25623.1.0.120231");
  script_cve_id("CVE-2012-5657");
  script_tag(name:"creation_date", value:"2015-09-08 11:20:58 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-06T14:03:07+0000");
  script_tag(name:"last_modification", value:"2022-01-06 14:03:07 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-153");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-153.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-ZendFramework' package(s) announced via the ALAS-2013-153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The (1) Zend_Feed_Rss and (2) Zend_Feed_Atom classes in Zend_Feed in Zend Framework 1.11.x before 1.11.15 and 1.12.x before 1.12.1 allow remote attackers to read arbitrary files, send HTTP requests to intranet servers, and possibly cause a denial of service (CPU and memory consumption) via an XML External Entity (XXE) attack.");

  script_tag(name:"affected", value:"'php-ZendFramework' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework", rpm:"php-ZendFramework~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Auth-Adapter-Ldap", rpm:"php-ZendFramework-Auth-Adapter-Ldap~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Apc", rpm:"php-ZendFramework-Cache-Backend-Apc~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Libmemcached", rpm:"php-ZendFramework-Cache-Backend-Libmemcached~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Memcached", rpm:"php-ZendFramework-Cache-Backend-Memcached~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Captcha", rpm:"php-ZendFramework-Captcha~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Mysqli", rpm:"php-ZendFramework-Db-Adapter-Mysqli~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo", rpm:"php-ZendFramework-Db-Adapter-Pdo~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Mssql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Mssql~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Mysql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Mysql~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Pgsql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Pgsql~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Dojo", rpm:"php-ZendFramework-Dojo~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Feed", rpm:"php-ZendFramework-Feed~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Ldap", rpm:"php-ZendFramework-Ldap~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Pdf", rpm:"php-ZendFramework-Pdf~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Search-Lucene", rpm:"php-ZendFramework-Search-Lucene~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Serializer-Adapter-Igbinary", rpm:"php-ZendFramework-Serializer-Adapter-Igbinary~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Services", rpm:"php-ZendFramework-Services~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Soap", rpm:"php-ZendFramework-Soap~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-demos", rpm:"php-ZendFramework-demos~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-extras", rpm:"php-ZendFramework-extras~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-full", rpm:"php-ZendFramework-full~1.12.1~1.6.amzn1", rls:"AMAZON"))) {
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
