# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856433");
  script_version("2024-09-12T07:59:53+0000");
  script_cve_id("CVE-2024-40776", "CVE-2024-40779", "CVE-2024-40780", "CVE-2024-40782", "CVE-2024-40785", "CVE-2024-40789", "CVE-2024-40794", "CVE-2024-4558");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-23 15:38:01 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-06 04:01:11 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:3109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3109-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2QJZNFEZBZOW7NM6D54W6525OKVEHEU3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:3109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.44.3 (bsc#1228696 bsc#1228697 bsc#1228698):

  * Fix web process cache suspend/resume when sandbox is enabled.

  * Fix accelerated images disappearing after scrolling.

  * Fix video flickering with DMA-BUF sink.

  * Fix pointer lock on X11.

  * Fix movement delta on mouse events in GTK3.

  * Undeprecate console message API and make it available in 2022 API.

  * Fix several crashes and rendering issues.

  * Security fixes: CVE-2024-40776, CVE-2024-40779, CVE-2024-40780,
      CVE-2024-40782, CVE-2024-40785, CVE-2024-40789, CVE-2024-40794,
      CVE-2024-4558.

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang", rpm:"WebKitGTK-4.0-lang~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang", rpm:"WebKitGTK-4.1-lang~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2-4.0", rpm:"typelib-1.0-WebKit2-4.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0", rpm:"libjavascriptcoregtk-4.1-0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo", rpm:"webkit2gtk4-minibrowser-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles", rpm:"webkit2gtk-4.0-injected-bundles~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18", rpm:"libjavascriptcoregtk-4.0-18~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles", rpm:"webkit2gtk-4.1-injected-bundles~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-debuginfo", rpm:"libjavascriptcoregtk-6.0-1-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-debuginfo", rpm:"webkitgtk-6.0-injected-bundles-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-debuginfo", rpm:"webkit2gtk-4.1-injected-bundles-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource", rpm:"webkit2gtk3-soup2-debugsource~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37", rpm:"libwebkit2gtk-4.0-37~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-debuginfo", rpm:"libjavascriptcoregtk-4.0-18-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2WebExtension-4.0", rpm:"typelib-1.0-WebKit2WebExtension-4.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-JavaScriptCore-4.0", rpm:"typelib-1.0-JavaScriptCore-4.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-debuginfo", rpm:"webkit2gtk-4.0-injected-bundles-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel", rpm:"webkit2gtk4-devel~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles", rpm:"webkitgtk-6.0-injected-bundles~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser", rpm:"webkit2gtk3-soup2-minibrowser~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit-6.0", rpm:"typelib-1.0-WebKit-6.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-debuginfo", rpm:"libwebkit2gtk-4.0-37-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~6.0~debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource", rpm:"webkit2gtk4-debugsource~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-debuginfo", rpm:"libwebkitgtk-6.0-4-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-JavaScriptCore-4.1", rpm:"typelib-1.0-JavaScriptCore-4.1~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0", rpm:"libwebkit2gtk-4.1-0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser", rpm:"webkit2gtk4-minibrowser~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-debuginfo", rpm:"libwebkit2gtk-4.1-0-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2-4.1", rpm:"typelib-1.0-WebKit2-4.1~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4", rpm:"libwebkitgtk-6.0-4~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1", rpm:"libjavascriptcoregtk-6.0-1~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~4.1~debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKitWebProcessExtension-6.0", rpm:"typelib-1.0-WebKitWebProcessExtension-6.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-JavaScriptCore-6.0", rpm:"typelib-1.0-JavaScriptCore-6.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~6.0~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-debuginfo", rpm:"libjavascriptcoregtk-4.1-0-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2WebExtension-4.1", rpm:"typelib-1.0-WebKit2WebExtension-4.1~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~4.1~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit", rpm:"libjavascriptcoregtk-4.1-0-32bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit", rpm:"libwebkit2gtk-4.1-0-32bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-debuginfo", rpm:"libwebkit2gtk-4.0-37-32bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-debuginfo", rpm:"libjavascriptcoregtk-4.1-0-32bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit", rpm:"libwebkit2gtk-4.0-37-32bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-4.0-18-32bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-debuginfo", rpm:"libwebkit2gtk-4.1-0-32bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit", rpm:"libjavascriptcoregtk-4.0-18-32bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit-debuginfo", rpm:"libjavascriptcoregtk-4.1-0-64bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit-debuginfo", rpm:"libwebkit2gtk-4.1-0-64bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit", rpm:"libjavascriptcoregtk-4.1-0-64bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit-debuginfo", rpm:"libwebkit2gtk-4.0-37-64bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit", rpm:"libwebkit2gtk-4.1-0-64bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit", rpm:"libwebkit2gtk-4.0-37-64bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit", rpm:"libjavascriptcoregtk-4.0-18-64bit~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit-debuginfo", rpm:"libjavascriptcoregtk-4.0-18-64bit-debuginfo~2.44.3~150600.12.9.1", rls:"openSUSELeap15.6"))) {
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
