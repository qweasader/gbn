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
  script_oid("1.3.6.1.4.1.25623.1.0.851926");
  script_version("2021-06-28T02:00:39+0000");
  script_tag(name:"last_modification", value:"2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-10-06 08:17:19 +0200 (Sat, 06 Oct 2018)");
  script_cve_id("CVE-2018-15908", "CVE-2018-15909", "CVE-2018-15910", "CVE-2018-15911", "CVE-2018-16509", "CVE-2018-16510", "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16539", "CVE-2018-16540", "CVE-2018-16541", "CVE-2018-16542", "CVE-2018-16543", "CVE-2018-16585", "CVE-2018-16802", "CVE-2018-17183");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ghostscript (openSUSE-SU-2018:3036-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript to version 9.25 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-17183: Remote attackers were be able to supply crafted
  PostScript to potentially overwrite or replace error handlers to inject
  code (bsc#1109105)

  - CVE-2018-15909: Prevent type confusion using the .shfill operator that
  could have been used by attackers able to supply crafted PostScript
  files to crash the interpreter or potentially execute code (bsc#1106172).

  - CVE-2018-15908: Prevent attackers that are able to supply malicious
  PostScript files to bypass .tempfile restrictions and write files
  (bsc#1106171).

  - CVE-2018-15910: Prevent a type confusion in the LockDistillerParams
  parameter that could have been used to crash the interpreter or execute
  code (bsc#1106173).

  - CVE-2018-15911: Prevent use uninitialized memory access in the aesdecode
  operator that could have been used to crash the interpreter or
  potentially execute code (bsc#1106195).

  - CVE-2018-16513: Prevent a type confusion in the setcolor function that
  could have been used to crash the interpreter or possibly have
  unspecified other impact (bsc#1107412).

  - CVE-2018-16509: Incorrect 'restoration of privilege' checking during
  handling
  of /invalidaccess exceptions could be have been used by attackers able
  to supply crafted PostScript to execute code using the 'pipe'
  instruction (bsc#1107410).

  - CVE-2018-16510: Incorrect exec stack handling in the 'CS' and 'SC' PDF
  primitives could have been used by remote attackers able to supply
  crafted PDFs to crash the interpreter or possibly have unspecified other
  impact (bsc#1107411).

  - CVE-2018-16542: Prevent attackers able to supply crafted PostScript
  files from using insufficient interpreter stack-size checking during
  error handling to crash the interpreter (bsc#1107413).

  - CVE-2018-16541: Prevent attackers able to supply crafted PostScript
  files from using incorrect free logic in pagedevice replacement to crash
  the interpreter (bsc#1107421).

  - CVE-2018-16540: Prevent use-after-free in copydevice handling that could
  have been used to crash the interpreter or possibly have unspecified
  other impact (bsc#1107420).

  - CVE-2018-16539: Prevent attackers able to supply crafted PostScript
  files from using incorrect access checking in temp file handling to
  disclose contents
  of files on the system otherwise not readable (bsc#1107422).

  - CVE-2018-16543: gssetresolution and gsgetresolution allowed attackers to
  have an unspecified impact (bsc#1107423).

  - CVE-2018-16511: A type confusion in 'zty ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"ghostscript on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:3036-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00011.html");
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
  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini", rpm:"ghostscript-mini~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-debuginfo", rpm:"ghostscript-mini-debuginfo~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-debugsource", rpm:"ghostscript-mini-debugsource~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-mini-devel", rpm:"ghostscript-mini-devel~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11-debuginfo", rpm:"ghostscript-x11-debuginfo~9.25~14.9.1", rls:"openSUSELeap42.3"))) {
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
