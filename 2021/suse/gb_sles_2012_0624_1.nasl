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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0624.1");
  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0624-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3|SLES10\.0SP4|SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0624-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120624-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'RPM' package(s) announced via the SUSE-SU-2012:0624-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were reported in RPM which could have been exploited via specially crafted RPM files to cause a denial of service (application crash) or potentially allow attackers to execute arbitrary code.

Additionally, a non-security issue has been fixed that could have caused a division by zero in cycles calculation under rare circumstances.

Security Issue references:

 * CVE-2012-0815
>
 * CVE-2012-0060
>
 * CVE-2012-0061
>");

  script_tag(name:"affected", value:"'RPM' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP3, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP1, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"popt", rpm:"popt~1.7~271.37.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-32bit", rpm:"popt-32bit~1.7~271.37.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-devel", rpm:"popt-devel~1.7~271.37.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-devel-32bit", rpm:"popt-devel-32bit~1.7~271.37.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.4.2~43.38.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.4.2~43.38.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.4.2~43.38.42.36", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"popt", rpm:"popt~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-32bit", rpm:"popt-32bit~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-64bit", rpm:"popt-64bit~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-devel", rpm:"popt-devel~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-devel-32bit", rpm:"popt-devel-32bit~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-devel-64bit", rpm:"popt-devel-64bit~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-x86", rpm:"popt-x86~1.7~271.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.4.2~43.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.4.2~43.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.4.2~43.46.16", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"popt", rpm:"popt~1.7~37.29.33.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-32bit", rpm:"popt-32bit~1.7~37.29.33.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-x86", rpm:"popt-x86~1.7~37.29.33.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-32bit", rpm:"rpm-32bit~4.4.2.3~37.29.33.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.4.2.3~37.29.33.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-x86", rpm:"rpm-x86~4.4.2.3~37.29.33.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"popt", rpm:"popt~1.7~37.50.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-32bit", rpm:"popt-32bit~1.7~37.50.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"popt-x86", rpm:"popt-x86~1.7~37.50.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-32bit", rpm:"rpm-32bit~4.4.2.3~37.50.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.4.2.3~37.50.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-x86", rpm:"rpm-x86~4.4.2.3~37.50.6", rls:"SLES11.0SP2"))) {
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
