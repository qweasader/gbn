# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852475");
  script_version("2022-10-13T10:20:57+0000");
  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808",
                "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5812",
                "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5816",
                "CVE-2019-5817", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820",
                "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-10-13 10:20:57 +0000 (Thu, 13 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-11 14:43:00 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-05-05 02:00:44 +0000 (Sun, 05 May 2019)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2019:1325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1325-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:1325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  Chromium was updated to 74.0.3729.108 boo#1133313:

  * CVE-2019-5805: Use after free in PDFium

  * CVE-2019-5806: Integer overflow in Angle

  * CVE-2019-5807: Memory corruption in V8

  * CVE-2019-5808: Use after free in Blink

  * CVE-2019-5809: Use after free in Blink

  * CVE-2019-5810: User information disclosure in Autofill

  * CVE-2019-5811: CORS bypass in Blink

  * CVE-2019-5813: Out of bounds read in V8

  * CVE-2019-5814: CORS bypass in Blink

  * CVE-2019-5815: Heap buffer overflow in Blink

  * CVE-2019-5818: Uninitialized value in media reader

  * CVE-2019-5819: Incorrect escaping in developer tools

  * CVE-2019-5820: Integer overflow in PDFium

  * CVE-2019-5821: Integer overflow in PDFium

  * CVE-2019-5822: CORS bypass in download manager

  * CVE-2019-5823: Forced navigation from service worker

  * CVE-2019-5812: URL spoof in Omnibox on iOS

  * CVE-2019-5816: Exploit persistence extension on Android

  * CVE-2019-5817: Heap buffer overflow in Angle on Windows

  - Update conditions to use system harfbuzz on TW+

  - Require java during build

  - Enable using pipewire when available

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1325=1");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~74.0.3729.108~lp150.209.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~74.0.3729.108~lp150.209.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~74.0.3729.108~lp150.209.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~74.0.3729.108~lp150.209.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~74.0.3729.108~lp150.209.2", rls:"openSUSELeap15.0"))) {
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
