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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1482.1");
  script_cve_id("CVE-2015-4000");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1482-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151482-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap2' package(s) announced via the SUSE-SU-2015:1482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"openldap2 was updated to fix one security issue.
This security issue was fixed:
- CVE-2015-4000: The Logjam Attack / weakdh.org (bsc#937766).
This non-security issue was fixed:
- bsc#932773: ldapmodify failed with DOS format LDIF files containing '-'
 separator.");

  script_tag(name:"affected", value:"'openldap2' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for VMWare 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"libldap-openssl1-2_4-2", rpm:"libldap-openssl1-2_4-2~2.4.26~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-openssl1-2_4-2-32bit", rpm:"libldap-openssl1-2_4-2-32bit~2.4.26~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-openssl1-2_4-2-x86", rpm:"libldap-openssl1-2_4-2-x86~2.4.26~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"compat-libldap-2_3-0", rpm:"compat-libldap-2_3-0~2.3.37~2.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.26~0.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.26~0.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-x86", rpm:"libldap-2_4-2-x86~2.4.26~0.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.26~0.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.26~0.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.26~0.35.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"compat-libldap-2_3-0", rpm:"compat-libldap-2_3-0~2.3.37~2.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.26~0.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.26~0.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-x86", rpm:"libldap-2_4-2-x86~2.4.26~0.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.26~0.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.26~0.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.26~0.35.1", rls:"SLES11.0SP4"))) {
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
