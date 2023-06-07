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
  script_oid("1.3.6.1.4.1.25623.1.0.852528");
  script_version("2021-09-07T09:01:33+0000");
  script_cve_id("CVE-2018-18511", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11694", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818", "CVE-2019-9819", "CVE-2019-9820");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 16:23:00 +0000 (Fri, 26 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-06-03 02:00:28 +0000 (Mon, 03 Jun 2019)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2019:1484-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2019:1484-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2019:1484-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  Mozilla Thunderbird was updated to 60.7.0

  * Attachment pane of Write window no longer focused when attaching files
  using a keyboard shortcut

  Security issues fixed (MFSA 2019-15 boo#1135824):

  * CVE-2018-18511: Cross-origin theft of images with
  ImageBitmapRenderingContext

  * CVE-2019-11691: Use-after-free in XMLHttpRequest

  * CVE-2019-11692: Use-after-free removing listeners in the event listener
  manager

  * CVE-2019-11693: Buffer overflow in WebGL bufferdata on Linux

  * CVE-2019-11694: (Windows only) Uninitialized memory memory leakage in
  Windows sandbox

  * CVE-2019-11698: Theft of user history data through drag and drop of
  hyperlinks to and from bookmarks

  * CVE-2019-5798: Out-of-bounds read in Skia

  * CVE-2019-7317: Use-after-free in png_image_free of libpng library

  * CVE-2019-9797: Cross-origin theft of images with createImageBitmap

  * CVE-2019-9800: Memory safety bugs fixed in Firefox 67 and Firefox ESR
  60.7

  * CVE-2019-9815: Disable hyperthreading on content JavaScript threads on
  macOS

  * CVE-2019-9816: Type confusion with object groups and UnboxedObjects

  * CVE-2019-9817: Stealing of cross-domain images using canvas

  * CVE-2019-9818: Use-after-free in crash generation server

  * CVE-2019-9819: Compartment mismatch with fetch API

  * CVE-2019-9820: Use-after-free of ChromeEventHandler by DocShell

  - Disable LTO (boo#1133267).

  - Add patch to fix build using rust-1.33: (boo#1130694)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1484=1");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 42.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~60.7.0~92.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~60.7.0~92.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~60.7.0~92.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~60.7.0~92.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~60.7.0~92.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~60.7.0~92.1", rls:"openSUSELeap42.3"))) {
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
