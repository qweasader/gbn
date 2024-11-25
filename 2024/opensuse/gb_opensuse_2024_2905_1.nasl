# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856361");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2024-40776", "CVE-2024-40779", "CVE-2024-40780", "CVE-2024-40782");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-15 16:47:58 +0000 (Thu, 15 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:05:28 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:2905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2905-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KOQ32VB3ACEHBT6F3XIQPZAFZXV27J2X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:2905-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  * CVE-2024-40776: Fixed a use-after-free issue with improved memory management
      (bsc#1228613).

  * CVE-2024-40779: Fixed a out-of-bounds read with improved bounds checking
      (bsc#1228693).

  * CVE-2024-40780: Fixed another out-of-bounds read with improved bounds
      checking (bsc#1228694).

  * CVE-2024-40782: Fixed a second use-after-free issue with improved memory
      management (bsc#1228695).

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

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0", rpm:"WebKitGTK-4.0~lang~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }


  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser", rpm:"webkit2gtk3-soup2-minibrowser~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1-debuginfo", rpm:"libjavascriptcoregtk-6.0-1-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-JavaScriptCore-4.1", rpm:"typelib-1.0-JavaScriptCore-4.1~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles", rpm:"webkit2gtk-4.0-injected-bundles~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles", rpm:"webkitgtk-6.0-injected-bundles~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.0-injected-bundles-debuginfo", rpm:"webkit2gtk-4.0-injected-bundles-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0", rpm:"libwebkit2gtk-4.1-0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit-6.0", rpm:"typelib-1.0-WebKit-6.0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel", rpm:"webkit2gtk4-devel~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0", rpm:"libjavascriptcoregtk-4.1-0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6.0-1", rpm:"libjavascriptcoregtk-6.0-1~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18", rpm:"libjavascriptcoregtk-4.0-18~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4", rpm:"libwebkitgtk-6.0-4~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-debuginfo", rpm:"libwebkit2gtk-4.1-0-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-debuginfo", rpm:"libjavascriptcoregtk-4.0-18-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser", rpm:"webkit2gtk4-minibrowser~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-JavaScriptCore-4.0", rpm:"typelib-1.0-JavaScriptCore-4.0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource", rpm:"webkit2gtk4-debugsource~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles", rpm:"webkit2gtk-4.1-injected-bundles~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37", rpm:"libwebkit2gtk-4.0-37~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-debuginfo", rpm:"libwebkit2gtk-4.0-37-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo", rpm:"webkit2gtk4-minibrowser-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2-4.0", rpm:"typelib-1.0-WebKit2-4.0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4.1-injected-bundles-debuginfo", rpm:"webkit2gtk-4.1-injected-bundles-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1", rpm:"webkit-jsc-4.1~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKitWebProcessExtension-6.0", rpm:"typelib-1.0-WebKitWebProcessExtension-6.0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-JavaScriptCore-6.0", rpm:"typelib-1.0-JavaScriptCore-6.0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource", rpm:"webkit2gtk3-soup2-debugsource~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2WebExtension-4.0", rpm:"typelib-1.0-WebKit2WebExtension-4_0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1", rpm:"webkit-jsc-4.1~debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0", rpm:"webkit-jsc-6.0~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0-debuginfo", rpm:"webkit-jsc-6.0-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-debuginfo", rpm:"libjavascriptcoregtk-4.1-0-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6.0-injected-bundles-debuginfo", rpm:"webkitgtk-6.0-injected-bundles-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.2.44.2", rpm:"webkit-jsc-4.2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2WebExtension-4.1", rpm:"typelib-1.0-WebKit2WebExtension-4.1~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6.0-4-debuginfo", rpm:"libwebkitgtk-6.0-4-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1.0-WebKit2-4.1", rpm:"typelib-1.0-WebKit2-4.1~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-4.0-18-32bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit-debuginfo", rpm:"libwebkit2gtk-4.0-37-32bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit-debuginfo", rpm:"libwebkit2gtk-4.1-0-32bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-32bit", rpm:"libwebkit2gtk-4.1-0-32bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-32bit", rpm:"libwebkit2gtk-4.0-37-32bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit", rpm:"libjavascriptcoregtk-4.1-0-32bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-32bit-debuginfo", rpm:"libjavascriptcoregtk-4.1-0-32bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-32bit", rpm:"libjavascriptcoregtk-4.0-18-32bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit-debuginfo", rpm:"libjavascriptcoregtk-4.0-18-64bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit", rpm:"libwebkit2gtk-4.1-0-64bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit", rpm:"libjavascriptcoregtk-4.1-0-64bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.1-0-64bit-debuginfo", rpm:"libwebkit2gtk-4.1-0-64bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit", rpm:"libwebkit2gtk-4.0-37-64bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1-0-64bit-debuginfo", rpm:"libjavascriptcoregtk-4.1-0-64bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0-18-64bit", rpm:"libjavascriptcoregtk-4-18-64bit~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4.0-37-64bit-debuginfo", rpm:"libwebkit2gtk-4.0-37-64bit-debuginfo~2.44.2~150600.12.6.1", rls:"openSUSELeap15.6"))) {
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
