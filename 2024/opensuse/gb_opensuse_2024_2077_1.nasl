# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856263");
  script_version("2024-07-10T14:21:44+0000");
  script_cve_id("CVE-2022-48622");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:53:45 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-06-29 04:03:18 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for gdk (SUSE-SU-2024:2077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2077-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SOPZXF4WMQGREAGZHJWMEOKIHBNFUUDJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk'
  package(s) announced via the SUSE-SU-2024:2077-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdk-pixbuf fixes the following issues:

  gdk-pixbuf was updated to version 2.42.12:

  * Security issues fixed:

  * CVE-2022-48622: Fixed heap memory corruption on gdk-pixbuf (bsc#1219276)

  * Changes in version 2.42.12:

  * ani: Reject files with multiple INA or IART chunks,

  * ani: validate chunk size,

  * Updated translations.

  * Enable other image loaders such as xpm and xbm (bsc#1223903)

  * Changes in version 2.42.11:

  * Disable fringe loaders by default.

  * Introspection fixes.

  * Updated translations.

  * Changes in version 2.42.10:

  * Search for rst2man.py.

  * Update the memory size limit for JPEG images.

  * Updated translations.

  * Fixed loading of larger images

  * Avoid Bash specific syntax in baselibs postscript (bsc#1195391)

  ##");

  script_tag(name:"affected", value:"'gdk' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel", rpm:"gdk-pixbuf-devel~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixdata-2_0", rpm:"typelib-1_0-GdkPixdata-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-debugsource", rpm:"gdk-pixbuf-debugsource~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer", rpm:"gdk-pixbuf-thumbnailer~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer-debuginfo", rpm:"gdk-pixbuf-thumbnailer-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-debuginfo", rpm:"libgdk_pixbuf-2_0-0-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-debuginfo", rpm:"gdk-pixbuf-devel-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-debuginfo", rpm:"gdk-pixbuf-query-loaders-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit-debuginfo", rpm:"libgdk_pixbuf-2_0-0-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit", rpm:"gdk-pixbuf-devel-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit-debuginfo", rpm:"gdk-pixbuf-devel-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit-debuginfo", rpm:"gdk-pixbuf-query-loaders-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-64bit", rpm:"gdk-pixbuf-query-loaders-64bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-64bit", rpm:"gdk-pixbuf-devel-64bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-64bit-debuginfo", rpm:"libgdk_pixbuf-2_0-0-64bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-64bit-debuginfo", rpm:"gdk-pixbuf-devel-64bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-64bit", rpm:"libgdk_pixbuf-2_0-0-64bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-64bit-debuginfo", rpm:"gdk-pixbuf-query-loaders-64bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel", rpm:"gdk-pixbuf-devel~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixdata-2_0", rpm:"typelib-1_0-GdkPixdata-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-debugsource", rpm:"gdk-pixbuf-debugsource~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer", rpm:"gdk-pixbuf-thumbnailer~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer-debuginfo", rpm:"gdk-pixbuf-thumbnailer-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-debuginfo", rpm:"libgdk_pixbuf-2_0-0-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-debuginfo", rpm:"gdk-pixbuf-devel-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-debuginfo", rpm:"gdk-pixbuf-query-loaders-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit-debuginfo", rpm:"libgdk_pixbuf-2_0-0-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit", rpm:"gdk-pixbuf-devel-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit-debuginfo", rpm:"gdk-pixbuf-devel-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit-debuginfo", rpm:"gdk-pixbuf-query-loaders-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-64bit", rpm:"gdk-pixbuf-query-loaders-64bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-64bit", rpm:"gdk-pixbuf-devel-64bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-64bit-debuginfo", rpm:"libgdk_pixbuf-2_0-0-64bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-64bit-debuginfo", rpm:"gdk-pixbuf-devel-64bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-64bit", rpm:"libgdk_pixbuf-2_0-0-64bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-64bit-debuginfo", rpm:"gdk-pixbuf-query-loaders-64bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel", rpm:"gdk-pixbuf-devel~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixdata-2_0", rpm:"typelib-1_0-GdkPixdata-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-debugsource", rpm:"gdk-pixbuf-debugsource~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer", rpm:"gdk-pixbuf-thumbnailer~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer-debuginfo", rpm:"gdk-pixbuf-thumbnailer-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-debuginfo", rpm:"libgdk_pixbuf-2_0-0-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-debuginfo", rpm:"gdk-pixbuf-devel-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-debuginfo", rpm:"gdk-pixbuf-query-loaders-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit-debuginfo", rpm:"libgdk_pixbuf-2_0-0-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit", rpm:"gdk-pixbuf-devel-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit-debuginfo", rpm:"gdk-pixbuf-devel-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit-debuginfo", rpm:"gdk-pixbuf-query-loaders-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel", rpm:"gdk-pixbuf-devel~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixdata-2_0", rpm:"typelib-1_0-GdkPixdata-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-debugsource", rpm:"gdk-pixbuf-debugsource~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer", rpm:"gdk-pixbuf-thumbnailer~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer-debuginfo", rpm:"gdk-pixbuf-thumbnailer-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-debuginfo", rpm:"libgdk_pixbuf-2_0-0-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-debuginfo", rpm:"gdk-pixbuf-devel-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-debuginfo", rpm:"gdk-pixbuf-query-loaders-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit-debuginfo", rpm:"libgdk_pixbuf-2_0-0-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit", rpm:"gdk-pixbuf-devel-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit-debuginfo", rpm:"gdk-pixbuf-devel-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit-debuginfo", rpm:"gdk-pixbuf-query-loaders-32bit-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.42.12~150400.5.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-debugsource", rpm:"gdk-pixbuf-debugsource~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-debuginfo", rpm:"libgdk_pixbuf-2_0-0-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-debuginfo", rpm:"gdk-pixbuf-query-loaders-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-debugsource", rpm:"gdk-pixbuf-debugsource~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-debuginfo", rpm:"libgdk_pixbuf-2_0-0-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-debuginfo", rpm:"gdk-pixbuf-query-loaders-debuginfo~2.42.12~150400.5.9.1", rls:"openSUSELeapMicro5.4"))) {
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