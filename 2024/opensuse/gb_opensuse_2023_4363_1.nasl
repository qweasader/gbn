# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833817");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-37052", "CVE-2023-34872");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-25 20:17:15 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:02:45 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for poppler (SUSE-SU-2023:4363-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4363-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KFPMTB2PH6D57HV4Y3SWG5ENMBXH3JFB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the SUSE-SU-2023:4363-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  * CVE-2022-37052: Fixed a crash that could be triggered when opening a crafted
      file (bsc#1214726).

  * CVE-2023-34872: Fixed a remote denial-of-service in Outline.cc
      (bsc#1213888).

  ##");

  script_tag(name:"affected", value:"'poppler' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3-debuginfo", rpm:"libpoppler-qt6-3-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-devel", rpm:"libpoppler-qt6-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo", rpm:"libpoppler-cpp0-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6-debugsource", rpm:"poppler-qt6-debugsource~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-debugsource", rpm:"poppler-qt5-debugsource~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-debuginfo", rpm:"libpoppler117-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3", rpm:"libpoppler-qt6-3~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1", rpm:"libpoppler-qt5-1~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo", rpm:"libpoppler-qt5-1-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117", rpm:"libpoppler117~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit", rpm:"libpoppler-qt5-1-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-32bit-debuginfo", rpm:"libpoppler117-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit-debuginfo", rpm:"libpoppler-cpp0-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit-debuginfo", rpm:"libpoppler-qt5-1-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit", rpm:"libpoppler-cpp0-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit-debuginfo", rpm:"libpoppler-glib8-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit", rpm:"libpoppler-glib8-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-32bit", rpm:"libpoppler117-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit", rpm:"libpoppler-glib8-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-64bit", rpm:"libpoppler117-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit-debuginfo", rpm:"libpoppler-qt5-1-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit-debuginfo", rpm:"libpoppler-cpp0-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit", rpm:"libpoppler-qt5-1-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit", rpm:"libpoppler-cpp0-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-64bit-debuginfo", rpm:"libpoppler117-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit-debuginfo", rpm:"libpoppler-glib8-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3-debuginfo", rpm:"libpoppler-qt6-3-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-devel", rpm:"libpoppler-qt6-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo", rpm:"libpoppler-cpp0-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6-debugsource", rpm:"poppler-qt6-debugsource~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-debugsource", rpm:"poppler-qt5-debugsource~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-debuginfo", rpm:"libpoppler117-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3", rpm:"libpoppler-qt6-3~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1", rpm:"libpoppler-qt5-1~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo", rpm:"libpoppler-qt5-1-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117", rpm:"libpoppler117~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit", rpm:"libpoppler-qt5-1-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-32bit-debuginfo", rpm:"libpoppler117-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit-debuginfo", rpm:"libpoppler-cpp0-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit-debuginfo", rpm:"libpoppler-qt5-1-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit", rpm:"libpoppler-cpp0-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit-debuginfo", rpm:"libpoppler-glib8-32bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit", rpm:"libpoppler-glib8-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-32bit", rpm:"libpoppler117-32bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit", rpm:"libpoppler-glib8-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-64bit", rpm:"libpoppler117-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit-debuginfo", rpm:"libpoppler-qt5-1-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit-debuginfo", rpm:"libpoppler-cpp0-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit", rpm:"libpoppler-qt5-1-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit", rpm:"libpoppler-cpp0-64bit~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler117-64bit-debuginfo", rpm:"libpoppler117-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit-debuginfo", rpm:"libpoppler-glib8-64bit-debuginfo~22.01.0~150400.3.16.1", rls:"openSUSELeap15.4"))) {
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