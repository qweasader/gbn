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
  script_oid("1.3.6.1.4.1.25623.1.0.822543");
  script_version("2023-10-19T05:05:21+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-32893");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 21:15:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-09-24 01:01:57 +0000 (Sat, 24 Sep 2022)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2022:3351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3351-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ESDNNG2SHEWK3WUH73FPSMN7CO7LQU27");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2022:3351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  - CVE-2022-32893: Fixed several crashes and rendering issues (bsc#1202807).

  - Fixed WebKitGTK not allow to be used from non-main threads (bsc#1202169).");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.36.7~150200.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit-debuginfo", rpm:"libwebkit2gtk-4_0-37-32bit-debuginfo~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.36.7~150200.44.1", rls:"openSUSELeap15.3"))) {
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