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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3286.1");
  script_cve_id("CVE-2017-7500", "CVE-2017-7501");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3286-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183286-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm' package(s) announced via the SUSE-SU-2018:3286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rpm fixes the following issues:

These security issues were fixed:
CVE-2017-7500: rpm did not properly handle RPM installations when a
 destination path was a symbolic link to a directory, possibly changing
 ownership and permissions of an arbitrary directory, and RPM files being
 placed in an arbitrary destination (bsc#943457).

CVE-2017-7501: rpm used temporary files with predictable names when
 installing an RPM. An attacker with ability to write in a directory
 where files will be installed could create symbolic links to an
 arbitrary location and modify content, and possibly permissions to
 arbitrary files, which could be used for denial of service or possibly
 privilege escalation (bsc#943457)

This non-security issue was fixed:
Use ksym-provides tool [bsc#1077692]");

  script_tag(name:"affected", value:"'rpm' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm", rpm:"python3-rpm~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm-debuginfo", rpm:"python3-rpm-debuginfo~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm-debugsource", rpm:"python3-rpm-debugsource~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-32bit", rpm:"rpm-32bit~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build-debuginfo", rpm:"rpm-build-debuginfo~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-debuginfo-32bit", rpm:"rpm-debuginfo-32bit~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-debuginfo", rpm:"rpm-debuginfo~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-debugsource", rpm:"rpm-debugsource~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-python-debuginfo", rpm:"rpm-python-debuginfo~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-python-debugsource", rpm:"rpm-python-debugsource~4.11.2~16.16.1", rls:"SLES12.0SP3"))) {
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
