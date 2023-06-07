# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851660");
  script_version("2022-05-23T14:26:21+0000");
  script_tag(name:"last_modification", value:"2022-05-23 14:26:21 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2017-12-09 07:39:49 +0100 (Sat, 09 Dec 2017)");
  script_cve_id("CVE-2017-15408", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411",
                "CVE-2017-15412", "CVE-2017-15413", "CVE-2017-15415", "CVE-2017-15416",
                "CVE-2017-15417", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15420",
                "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425",
                "CVE-2017-15426", "CVE-2017-15427");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 16:00:00 +0000 (Wed, 31 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2017:3244-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Chromium 63.0.3239.84 fixes the following security issues:

  - CVE-2017-15408: Heap buffer overflow in PDFium

  - CVE-2017-15409: Out of bounds write in Skia

  - CVE-2017-15410: Use after free in PDFium

  - CVE-2017-15411: Use after free in PDFium

  - CVE-2017-15412: Use after free in libXML

  - CVE-2017-15413: Type confusion in WebAssembly

  - CVE-2017-15415: Pointer information disclosure in IPC call

  - CVE-2017-15416: Out of bounds read in Blink

  - CVE-2017-15417: Cross origin information disclosure in Skia

  - CVE-2017-15418: Use of uninitialized value in Skia

  - CVE-2017-15419: Cross origin leak of redirect URL in Blink

  - CVE-2017-15420: URL spoofing in Omnibox

  - CVE-2017-15422: Integer overflow in ICU

  - CVE-2017-15423: Issue with SPAKE implementation in BoringSSL

  - CVE-2017-15424: URL Spoof in Omnibox

  - CVE-2017-15425: URL Spoof in Omnibox

  - CVE-2017-15426: URL Spoof in Omnibox

  - CVE-2017-15427: Insufficient blocking of JavaScript in Omnibox");

  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:3244-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~63.0.3239.84~127.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~63.0.3239.84~127.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~63.0.3239.84~127.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~63.0.3239.84~127.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~63.0.3239.84~127.1", rls:"openSUSELeap42.3"))) {
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
