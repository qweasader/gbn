# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856241");
  script_version("2024-06-21T15:40:03+0000");
  script_cve_id("CVE-2024-23226", "CVE-2024-27834");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 15:40:03 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 04:00:41 +0000 (Wed, 19 Jun 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:2065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2065-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RAPNC5QP5AMU7MI36K55ZR2JLGLBBAIQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:2065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  * Update to version 2.44.2

  * CVE-2024-27834: Fixed a vulnerability where an attacker with arbitrary read
      and write capability may be able to bypass Pointer Authentication.
      (bsc#1225071)

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang-2.44.2", rpm:"WebKitGTK-4.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang-2.44.2", rpm:"WebKitGTK-4.1-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang-2.44.2", rpm:"WebKitGTK-6.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-debuginfo-2.44.2", rpm:"webkit-jsc-4.1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2-4.0-2.44.2", rpm:"typelib-1.0-WebKit2-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2-4.0-2.44.2", rpm:"webkit2gtk3-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2WebExtension-4.0-2.44.2", rpm:"typelib-1.0-WebKit2WebExtension-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-2.44.2", rpm:"libwebkitgtk-6.0-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-debuginfo-2.44.2", rpm:"libwebkitgtk-6.0-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource-2.44.2", rpm:"webkit2gtk3-soup2-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource-2.44.2", rpm:"webkit2gtk3-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2", rpm:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-2.44.2", rpm:"webkit-jsc-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource-2.44.2", rpm:"webkit2gtk4-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-2.44.2", rpm:"webkit2gtk4-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit-6.0-2.44.2", rpm:"typelib-1-0-WebKit-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo-2.44.2", rpm:"webkit-jsc-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel-2.44.2", rpm:"webkit2gtk3-soup2-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel-2.44.2", rpm:"webkit2gtk4-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-2.44.2", rpm:"libwebkit2gtk-4.0-37-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk4-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-6.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-2.44.2", rpm:"libwebkit2gtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.1-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.1-2.44.2", rpm:"typelib-1-0-WebKit2-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-2.44.2", rpm:"webkit-jsc-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0~debuginfo-2.44.2", rpm:"webkit-jsc-6.0~debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel-2.44.2", rpm:"webkit2gtk3-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit-2.44.2", rpm:"libwebkit2gtk-4.0-37-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit-2.44.2", rpm:"libwebkit2gtk-4.1-0-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang-2.44.2", rpm:"WebKitGTK-4.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang-2.44.2", rpm:"WebKitGTK-4.1-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang-2.44.2", rpm:"WebKitGTK-6.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-debuginfo-2.44.2", rpm:"webkit-jsc-4.1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.0-2.44.2", rpm:"typelib-1-0-WebKit2-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-2.44.2", rpm:"webkit2gtk3-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.0-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-2.44.2", rpm:"libwebkitgtk-6.0-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-debuginfo-2.44.2", rpm:"libwebkitgtk-6.0-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource-2.44.2", rpm:"webkit2gtk3-soup2-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource-2.44.2", rpm:"webkit2gtk3-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2", rpm:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-2.44.2", rpm:"webkit-jsc-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource-2.44.2", rpm:"webkit2gtk4-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-2.44.2", rpm:"webkit2gtk4-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit-6.0-2.44.2", rpm:"typelib-1-0-WebKit-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo-2.44.2", rpm:"webkit-jsc-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel-2.44.2", rpm:"webkit2gtk3-soup2-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel-2.44.2", rpm:"webkit2gtk4-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-2.44.2", rpm:"libwebkit2gtk-4.0-37-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk4-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-6.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-2.44.2", rpm:"libwebkit2gtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-2.44.2", rpm:"webkit-jsc-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.1-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.1-2.44.2", rpm:"typelib-1-0-WebKit2-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-2.44.2", rpm:"webkit-jsc-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-debuginfo-2.44.2", rpm:"webkit-jsc-6.0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel-2.44.2", rpm:"webkit2gtk3-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit-2.44.2", rpm:"libwebkit2gtk-4.0-37-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-64bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit-2.44.2", rpm:"libwebkit2gtk-4.1-0-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-64bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang-2.44.2", rpm:"WebKitGTK-4.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang-2.44.2", rpm:"WebKitGTK-4.1-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang-2.44.2", rpm:"WebKitGTK-6.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-debuginfo-2.44.2", rpm:"webkit-jsc-4.1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.0-2.44.2", rpm:"typelib-1-0-WebKit2-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-2.44.2", rpm:"libwebkitgtk-6.0-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.0-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-2.44.2", rpm:"webkit2gtk3-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-debuginfo-2.44.2", rpm:"libwebkitgtk-6.0-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2", rpm:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-2.44.2", rpm:"webkit-jsc-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource-2.44.2", rpm:"webkit2gtk3-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource-2.44.2", rpm:"webkit2gtk3-soup2-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource-2.44.2", rpm:"webkit2gtk4-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-2.44.2", rpm:"webkit2gtk4-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit-6.0-2.44.2", rpm:"typelib-1-0-WebKit-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo-2.44.2", rpm:"webkit-jsc-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel-2.44.2", rpm:"webkit2gtk3-soup2-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel-2.44.2", rpm:"webkit2gtk4-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-2.44.2", rpm:"libwebkit2gtk-4.0-37-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk4-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-6.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-2.44.2", rpm:"libwebkit2gtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-2.44.2", rpm:"webkit-jsc-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.1-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.1-2.44.2", rpm:"typelib-1-0-WebKit2-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-2.44.2", rpm:"webkit-jsc-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-debuginfo-2.44.2", rpm:"webkit-jsc-6.0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel-2.44.2", rpm:"webkit2gtk3-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang-2.44.2", rpm:"WebKitGTK-4.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang-2.44.2", rpm:"WebKitGTK-4.1-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang-2.44.2", rpm:"WebKitGTK-6.0-lang-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-debuginfo-2.44.2", rpm:"webkit-jsc-4.1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.0-2.44.2", rpm:"typelib-1-0-WebKit2-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-2.44.2", rpm:"libwebkitgtk-6.0-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.0-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-2.44.2", rpm:"webkit2gtk3-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-debuginfo-2.44.2", rpm:"libwebkitgtk-6.0-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2", rpm:"typelib-1-0-WebKitWebProcessExtension-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-2.44.2", rpm:"webkit-jsc-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-2.44.2", rpm:"webkit2gtk-4.1-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource-2.44.2", rpm:"webkit2gtk3-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource-2.44.2", rpm:"webkit2gtk3-soup2-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource-2.44.2", rpm:"webkit2gtk4-debugsource-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-2.44.2", rpm:"webkit2gtk4-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2", rpm:"typelib-1-0-WebKit2WebExtension-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit-6.0-2.44.2", rpm:"typelib-1-0-WebKit-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo-2.44.2", rpm:"webkit-jsc-4-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel-2.44.2", rpm:"webkit2gtk3-soup2-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel-2.44.2", rpm:"webkit2gtk4-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-2.44.2", rpm:"libwebkit2gtk-4.0-37-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk4-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-6.0-2.44.2", rpm:"typelib-1-0-JavaScriptCore-6.0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-2.44.2", rpm:"libwebkit2gtk-4.1-0-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1-2.44.2", rpm:"webkit-jsc-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-2.44.2", rpm:"libjavascriptcoregtk-6.0-1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-JavaScriptCore-4.1-2.44.2", rpm:"typelib-1-0-JavaScriptCore-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1-0-WebKit2-4.1-2.44.2", rpm:"typelib-1-0-WebKit2-4.1-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-2.44.2", rpm:"webkit2gtk3-soup2-minibrowser-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2", rpm:"webkitgtk-6.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-2.44.2", rpm:"webkit-jsc-4-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2", rpm:"webkit2gtk-4.0-injected-bundles-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-debuginfo-2.44.2", rpm:"webkit-jsc-6.0-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel-2.44.2", rpm:"webkit2gtk3-devel-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-2.44.2", rpm:"libjavascriptcoregtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2", rpm:"libwebkit2gtk-4.0-37-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2", rpm:"libjavascriptcoregtk-4.0-18-32bit-debuginfo-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-2.44.2", rpm:"libwebkit2gtk-4.1-0-32bit-2.44.2~150400.4.83.2", rls:"openSUSELeap15.5"))) {
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
