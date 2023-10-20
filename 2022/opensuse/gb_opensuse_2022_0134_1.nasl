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
  script_oid("1.3.6.1.4.1.25623.1.0.854385");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2021-33430", "CVE-2021-41496");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 16:41:00 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:34:22 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for python-numpy (openSUSE-SU-2022:0134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0134-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LQS3J3J4254A7C3LD55D7A432FZ2RFFI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-numpy'
  package(s) announced via the openSUSE-SU-2022:0134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-numpy fixes the following issues:

  - CVE-2021-33430: Fixed buffer overflow that could lead to DoS in
       PyArray_NewFromDescr_int function of ctors.c (bsc#1193913).

  - CVE-2021-41496: Fixed buffer overflow that could lead to DoS in
       array_from_pyobj function of fortranobject.c (bsc#1193907).");

  script_tag(name:"affected", value:"'python-numpy' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"python-numpy-debugsource", rpm:"python-numpy-debugsource~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-numpy_1_17_3-gnu-hpc-debugsource", rpm:"python-numpy_1_17_3-gnu-hpc-debugsource~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy", rpm:"python3-numpy~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-debuginfo", rpm:"python3-numpy-debuginfo~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-devel", rpm:"python3-numpy-devel~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-gnu-hpc", rpm:"python3-numpy-gnu-hpc~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-gnu-hpc-devel", rpm:"python3-numpy-gnu-hpc-devel~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy_1_17_3-gnu-hpc", rpm:"python3-numpy_1_17_3-gnu-hpc~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy_1_17_3-gnu-hpc-debuginfo", rpm:"python3-numpy_1_17_3-gnu-hpc-debuginfo~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy_1_17_3-gnu-hpc-devel", rpm:"python3-numpy_1_17_3-gnu-hpc-devel~1.17.3~10.1", rls:"openSUSELeap15.3"))) {
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