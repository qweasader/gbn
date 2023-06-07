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
  script_oid("1.3.6.1.4.1.25623.1.0.850760");
  script_version("2022-07-05T11:37:01+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:01 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-10-13 15:08:44 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2012-5615", "CVE-2014-0224", "CVE-2014-4274", "CVE-2014-4287",
                "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6474",
                "CVE-2014-6478", "CVE-2014-6484", "CVE-2014-6489", "CVE-2014-6491",
                "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6500",
                "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530",
                "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559", "CVE-2014-6564",
                "CVE-2014-6568", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382",
                "CVE-2015-0385", "CVE-2015-0391", "CVE-2015-0409", "CVE-2015-0411",
                "CVE-2015-0432");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for MySQL (SUSE-SU-2015:0620-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MySQL'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The MySQL datebase server was updated to 5.5.42, fixing various bugs and
  security issues.

  Also various issues with the mysql start script were fixed.
  (bsc#868673, bsc#878779)");

  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-42.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-41.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-40.html");

  script_tag(name:"affected", value:"MySQL on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:0620-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.42~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
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
