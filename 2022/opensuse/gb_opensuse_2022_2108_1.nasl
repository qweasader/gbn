# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854750");
  script_version("2022-06-17T14:04:08+0000");
  script_cve_id("CVE-2021-22904", "CVE-2022-23633");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-17 14:04:08 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 17:36:00 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2022-06-17 01:03:12 +0000 (Fri, 17 Jun 2022)");
  script_name("openSUSE: Security Advisory for rubygem-actionpack-5_1, (SUSE-SU-2022:2108-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2108-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/44OJ2RWG676EUNEQ2IHWMIKVPKTQT7GP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-actionpack-5_1, '
  package(s) announced via the SUSE-SU-2022:2108-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-actionpack-5_1 and rubygem-activesupport-5_1 fixes
     the following issues:

  - CVE-2021-22904: Fixed possible DoS Vulnerability in Action Controller
       Token Authentication (bsc#1185780)

  - CVE-2022-23633: Fixed possible exposure of information vulnerability in
       Action Pack (bsc#1196182)");

  script_tag(name:"affected", value:"'rubygem-actionpack-5_1, ' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-5_1", rpm:"ruby2.5-rubygem-actionpack-5_1~5.1.4~150000.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-doc-5_1", rpm:"ruby2.5-rubygem-actionpack-doc-5_1~5.1.4~150000.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-activesupport-5_1", rpm:"ruby2.5-rubygem-activesupport-5_1~5.1.4~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-activesupport-doc-5_1", rpm:"ruby2.5-rubygem-activesupport-doc-5_1~5.1.4~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-5_1", rpm:"ruby2.5-rubygem-actionpack-5_1~5.1.4~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-doc-5_1", rpm:"ruby2.5-rubygem-actionpack-doc-5_1~5.1.4~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-activesupport-5_1", rpm:"ruby2.5-rubygem-activesupport-5_1~5.1.4~150000.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-activesupport-doc-5_1", rpm:"ruby2.5-rubygem-activesupport-doc-5_1~5.1.4~150000.3.6.1", rls:"openSUSELeap15.3"))) {
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