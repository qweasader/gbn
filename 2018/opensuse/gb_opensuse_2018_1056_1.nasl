# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851736");
  script_version("2021-06-28T11:00:33+0000");
  script_tag(name:"last_modification", value:"2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-25 08:41:02 +0200 (Wed, 25 Apr 2018)");
  script_cve_id("CVE-2016-4330", "CVE-2016-4331", "CVE-2016-4332", "CVE-2016-4333");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for hdf5 (openSUSE-SU-2018:1056-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5 fixes the following issues:

  - fix security issues (arbitrary code execution): CVE-2016-4330: H5T_ARRAY
  Code Execution (boo#1011201) CVE-2016-4331: H5Z_NBIT Code Execution
  (boo#1011204) CVE-2016-4332: Shareable Message Type Code Execution
  (boo#1011205) CVE-2016-4333: Array index bounds issue (boo#1011198)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-392=1");

  script_tag(name:"affected", value:"hdf5 on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1056-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-04/msg00068.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"hdf5", rpm:"hdf5~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-debuginfo", rpm:"hdf5-debuginfo~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-debugsource", rpm:"hdf5-debugsource~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-devel", rpm:"hdf5-devel~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-devel-data", rpm:"hdf5-devel-data~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-devel-static", rpm:"hdf5-devel-static~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-examples", rpm:"hdf5-examples~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-openmpi", rpm:"hdf5-openmpi~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-openmpi-debuginfo", rpm:"hdf5-openmpi-debuginfo~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-openmpi-devel", rpm:"hdf5-openmpi-devel~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-openmpi-devel-static", rpm:"hdf5-openmpi-devel-static~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-10", rpm:"libhdf5-10~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-10-debuginfo", rpm:"libhdf5-10-debuginfo~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-10-openmpi", rpm:"libhdf5-10-openmpi~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-10-openmpi-debuginfo", rpm:"libhdf5-10-openmpi-debuginfo~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl10", rpm:"libhdf5_hl10~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl10-debuginfo", rpm:"libhdf5_hl10-debuginfo~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl10-openmpi", rpm:"libhdf5_hl10-openmpi~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl10-openmpi-debuginfo", rpm:"libhdf5_hl10-openmpi-debuginfo~1.8.15~7.3.1", rls:"openSUSELeap42.3"))) {
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
