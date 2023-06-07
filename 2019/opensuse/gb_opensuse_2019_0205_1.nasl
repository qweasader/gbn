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
  script_oid("1.3.6.1.4.1.25623.1.0.852300");
  script_version("2021-09-07T10:01:34+0000");
  script_cve_id("CVE-2019-5754", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757",
                "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5761",
                "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764", "CVE-2019-5765",
                "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768", "CVE-2019-5769",
                "CVE-2019-5770", "CVE-2019-5771", "CVE-2019-5772", "CVE-2019-5773",
                "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777",
                "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780", "CVE-2019-5781",
                "CVE-2019-5782", "CVE-2019-5784");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-17 17:20:00 +0000 (Wed, 17 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-19 04:06:09 +0100 (Tue, 19 Feb 2019)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2019:0205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2019:0205-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00045.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:0205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Chromium to version 72.0.3626.96
  fixes the following issues:

  Security issues fixed (bsc#1123641 and bsc#1124936):

  - CVE-2019-5784: Inappropriate implementation in V8

  - CVE-2019-5754: Inappropriate implementation in QUIC Networking.

  - CVE-2019-5782: Inappropriate implementation in V8.

  - CVE-2019-5755: Inappropriate implementation in V8.

  - CVE-2019-5756: Use after free in PDFium.

  - CVE-2019-5757: Type Confusion in SVG.

  - CVE-2019-5758: Use after free in Blink.

  - CVE-2019-5759: Use after free in HTML select elements.

  - CVE-2019-5760: Use after free in WebRTC.

  - CVE-2019-5761: Use after free in SwiftShader.

  - CVE-2019-5762: Use after free in PDFium.

  - CVE-2019-5763: Insufficient validation of untrusted input in V8.

  - CVE-2019-5764: Use after free in WebRTC.

  - CVE-2019-5765: Insufficient policy enforcement in the browser.

  - CVE-2019-5766: Insufficient policy enforcement in Canvas.

  - CVE-2019-5767: Incorrect security UI in WebAPKs.

  - CVE-2019-5768: Insufficient policy enforcement in DevTools.

  - CVE-2019-5769: Insufficient validation of untrusted input in Blink.

  - CVE-2019-5770: Heap buffer overflow in WebGL.

  - CVE-2019-5771: Heap buffer overflow in SwiftShader.

  - CVE-2019-5772: Use after free in PDFium.

  - CVE-2019-5773: Insufficient data validation in IndexedDB.

  - CVE-2019-5774: Insufficient validation of untrusted input in
  SafeBrowsing.

  - CVE-2019-5775: Insufficient policy enforcement in Omnibox.

  - CVE-2019-5776: Insufficient policy enforcement in Omnibox.

  - CVE-2019-5777: Insufficient policy enforcement in Omnibox.

  - CVE-2019-5778: Insufficient policy enforcement in Extensions.

  - CVE-2019-5779: Insufficient policy enforcement in ServiceWorker.

  - CVE-2019-5780: Insufficient policy enforcement.

  - CVE-2019-5781: Insufficient policy enforcement in Omnibox.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-205=1");

  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3.");

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
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~72.0.3626.96~197.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~72.0.3626.96~197.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~72.0.3626.96~197.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~72.0.3626.96~197.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~72.0.3626.96~197.1", rls:"openSUSELeap42.3"))) {
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
