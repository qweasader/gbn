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
  script_oid("1.3.6.1.4.1.25623.1.0.814566");
  script_version("2021-06-28T11:00:33+0000");
  script_cve_id("CVE-2018-17183", "CVE-2018-17961", "CVE-2018-18073",
                "CVE-2018-18284", "CVE-2018-19409", "CVE-2018-19475",
                "CVE-2018-19476", "CVE-2018-19477");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-12-18 07:41:34 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for ghostscript (openSUSE-SU-2018:4140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2018:4140-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00038.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the openSUSE-SU-2018:4140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript to version 9.26 fixes the following issues:

  Security issues fixed:

  - CVE-2018-19475: Fixed bypass of an intended access restriction in
  psi/zdevice2.c (bsc#1117327)

  - CVE-2018-19476: Fixed bypass of an intended access restriction in
  psi/zicc.c (bsc#1117313)

  - CVE-2018-19477: Fixed bypass of an intended access restriction in
  psi/zfjbig2.c (bsc#1117274)

  - CVE-2018-19409: Check if another device is used correctly in
  LockSafetyParams (bsc#1117022)

  - CVE-2018-18284: Fixed potential sandbox escape through 1Policy operator
  (bsc#1112229)

  - CVE-2018-18073: Fixed leaks through operator in saved execution stacks
  (bsc#1111480)

  - CVE-2018-17961: Fixed a -dSAFER sandbox escape by bypassing executeonly
  (bsc#1111479)

  - CVE-2018-17183: Fixed a potential code injection by specially crafted
  PostScript files (bsc#1109105)

  Version update to 9.26 (bsc#1117331):

  - Security issues have been the primary focus

  - Minor bug fixes and improvements

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1556=1");

  script_tag(name:"affected", value:"ghostscript on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini", rpm:"ghostscript-mini~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-debuginfo", rpm:"ghostscript-mini-debuginfo~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-debugsource", rpm:"ghostscript-mini-debugsource~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-devel", rpm:"ghostscript-mini-devel~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11-debuginfo", rpm:"ghostscript-x11-debuginfo~9.26~14.12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre-debugsource", rpm:"libspectre-debugsource~0.2.7~17.4.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre-devel", rpm:"libspectre-devel~0.2.7~17.4.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre1", rpm:"libspectre1~0.2.7~17.4.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre1-debuginfo", rpm:"libspectre1-debuginfo~0.2.7~17.4.2", rls:"openSUSELeap42.3"))) {
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
