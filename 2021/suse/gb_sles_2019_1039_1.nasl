# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1039.1");
  script_cve_id("CVE-2019-11234", "CVE-2019-11235");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-13 18:29:00 +0000 (Mon, 13 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1039-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1039-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191039-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius-server' package(s) announced via the SUSE-SU-2019:1039-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freeradius-server fixes the following issues:

Security issues fixed:
CVE-2019-11235: Fixed an authentication bypass related to the EAP-PWD
 Commit frame and insufficent validation of elliptic curve points
 (bsc#1132549).

CVE-2019-11234: Fixed an authentication bypass caused by reflecting
 privous values back to the server (bsc#1132664).");

  script_tag(name:"affected", value:"'freeradius-server' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5-debuginfo", rpm:"freeradius-server-krb5-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap-debuginfo", rpm:"freeradius-server-ldap-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql-debuginfo", rpm:"freeradius-server-mysql-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl-debuginfo", rpm:"freeradius-server-perl-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql-debuginfo", rpm:"freeradius-server-postgresql-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python", rpm:"freeradius-server-python~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python-debuginfo", rpm:"freeradius-server-python-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite-debuginfo", rpm:"freeradius-server-sqlite-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~3.0.3~17.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5-debuginfo", rpm:"freeradius-server-krb5-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap-debuginfo", rpm:"freeradius-server-ldap-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql-debuginfo", rpm:"freeradius-server-mysql-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl-debuginfo", rpm:"freeradius-server-perl-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql-debuginfo", rpm:"freeradius-server-postgresql-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python", rpm:"freeradius-server-python~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python-debuginfo", rpm:"freeradius-server-python-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite-debuginfo", rpm:"freeradius-server-sqlite-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5-debuginfo", rpm:"freeradius-server-krb5-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap-debuginfo", rpm:"freeradius-server-ldap-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql-debuginfo", rpm:"freeradius-server-mysql-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl-debuginfo", rpm:"freeradius-server-perl-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql-debuginfo", rpm:"freeradius-server-postgresql-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python", rpm:"freeradius-server-python~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python-debuginfo", rpm:"freeradius-server-python-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite-debuginfo", rpm:"freeradius-server-sqlite-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~3.0.3~17.12.1", rls:"SLES12.0SP2"))) {
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
