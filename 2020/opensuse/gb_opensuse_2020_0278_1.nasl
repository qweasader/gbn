# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853057");
  script_version("2021-08-12T09:01:18+0000");
  script_cve_id("CVE-2019-8835", "CVE-2019-8844", "CVE-2019-8846", "CVE-2020-3862", "CVE-2020-3864", "CVE-2020-3865", "CVE-2020-3867", "CVE-2020-3868");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:19:00 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2020-03-03 04:01:23 +0000 (Tue, 03 Mar 2020)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (openSUSE-SU-2020:0278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0278-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2020:0278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 to version 2.26.4 fixes the following issues:

  Security issues fixed:

  - CVE-2019-8835: Fixed multiple memory corruption issues (bsc#1161719).

  - CVE-2019-8844: Fixed multiple memory corruption issues (bsc#1161719).

  - CVE-2019-8846: Fixed a use-after-free issue (bsc#1161719).

  - CVE-2020-3862: Fixed a memory handling issue (bsc#1163809).

  - CVE-2020-3864: Fixed a logic issue in the DOM object context handling
  (bsc#1163809).

  - CVE-2020-3865: Fixed a logic issue in the DOM object context handling
  (bsc#1163809).

  - CVE-2020-3867: Fixed an XSS issue (bsc#1163809).

  - CVE-2020-3868: Fixed multiple memory corruption issues that could have
  lead to arbitrary code execution (bsc#1163809).

  Non-security issues fixed:

  - Fixed issues while trying to play a video on NextCloud.

  - Fixed vertical alignment of text containing arabic diacritics.

  - Fixed build with icu 65.1.

  - Fixed page loading errors with websites using HSTS.

  - Fixed web process crash when displaying a KaTeX formula.

  - Fixed several crashes and rendering issues.

  - Switched to a single web process for Evolution and geary (bsc#1159329
  glgo#GNOME/evolution#587).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-278=1");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit-debuginfo", rpm:"libwebkit2gtk-4_0-37-32bit-debuginfo~2.26.4~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
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