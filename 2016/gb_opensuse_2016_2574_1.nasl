# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851413");
  script_version("2021-10-14T11:01:30+0000");
  script_tag(name:"last_modification", value:"2021-10-14 11:01:30 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-10-21 05:54:14 +0200 (Fri, 21 Oct 2016)");
  script_cve_id("CVE-2013-5653", "CVE-2016-7978", "CVE-2016-7979");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ghostscript-library (openSUSE-SU-2016:2574-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript-library'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript-library fixes the following issues:

  - Multiple security vulnerabilities have been discovered where
  ghostscript's '-dsafer' flag did not provide sufficient protection
  against unintended access to the file system. Thus, a machine that would
  process a specially crafted Postscript file would potentially leak
  sensitive information to an attacker. (CVE-2013-5653, bsc#1001951)

  - An incorrect reference count was found in .setdevice. This issue lead to
  a use-after-free scenario, which could have been exploited for
  denial-of-service or, possibly, arbitrary code execution attacks.
  (CVE-2016-7978, bsc#1001951)

  - Insufficient validation of the type of input in .initialize_dsc_parser
  used to allow remote code execution. (CVE-2016-7979, bsc#1001951)

  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"ghostscript-library on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2574-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini", rpm:"ghostscript-mini~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-debuginfo", rpm:"ghostscript-mini-debuginfo~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-debugsource", rpm:"ghostscript-mini-debugsource~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-devel", rpm:"ghostscript-mini-devel~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.15~8.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11-debuginfo", rpm:"ghostscript-x11-debuginfo~9.15~8.1", rls:"openSUSELeap42.1"))) {
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
