# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856300");
  script_version("2024-07-24T05:06:37+0000");
  script_cve_id("CVE-2024-6239");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-24 19:06:27 +0000 (Mon, 24 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 04:01:04 +0000 (Wed, 10 Jul 2024)");
  script_name("openSUSE: Security Advisory for poppler (SUSE-SU-2024:2332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2332-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y4WGXGEVHVT22GPYTXOB4PO3JNEVR2Q6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the SUSE-SU-2024:2332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  * CVE-2024-6239: Fixed crash when using pdfinfo with -dests parameter on
      malformed input files (bsc#1226916).

  ##");

  script_tag(name:"affected", value:"'poppler' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6-debugsource", rpm:"poppler-qt6-debugsource~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1", rpm:"libpoppler-qt5-1~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo", rpm:"libpoppler-qt5-1-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo", rpm:"libpoppler-cpp0-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3", rpm:"libpoppler-qt6-3~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-debugsource", rpm:"poppler-qt5-debugsource~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3-debuginfo", rpm:"libpoppler-qt6-3-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-devel", rpm:"libpoppler-qt6-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-debuginfo", rpm:"libpoppler126-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126", rpm:"libpoppler126~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit", rpm:"libpoppler-glib8-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit-debuginfo", rpm:"libpoppler-cpp0-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-32bit-debuginfo", rpm:"libpoppler126-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit", rpm:"libpoppler-cpp0-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit-debuginfo", rpm:"libpoppler-glib8-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit", rpm:"libpoppler-qt5-1-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit-debuginfo", rpm:"libpoppler-qt5-1-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-32bit", rpm:"libpoppler126-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit", rpm:"libpoppler-qt5-1-64bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-64bit-debuginfo", rpm:"libpoppler126-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit-debuginfo", rpm:"libpoppler-qt5-1-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-64bit", rpm:"libpoppler126-64bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit-debuginfo", rpm:"libpoppler-cpp0-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit", rpm:"libpoppler-cpp0-64bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit-debuginfo", rpm:"libpoppler-glib8-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit", rpm:"libpoppler-glib8-64bit~23.01.0~150500.3.11.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6-debugsource", rpm:"poppler-qt6-debugsource~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1", rpm:"libpoppler-qt5-1~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo", rpm:"libpoppler-qt5-1-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo", rpm:"libpoppler-cpp0-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3", rpm:"libpoppler-qt6-3~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-debugsource", rpm:"poppler-qt5-debugsource~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-3-debuginfo", rpm:"libpoppler-qt6-3-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt6-devel", rpm:"libpoppler-qt6-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-debuginfo", rpm:"libpoppler126-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126", rpm:"libpoppler126~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit", rpm:"libpoppler-glib8-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit-debuginfo", rpm:"libpoppler-cpp0-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-32bit-debuginfo", rpm:"libpoppler126-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit", rpm:"libpoppler-cpp0-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit-debuginfo", rpm:"libpoppler-glib8-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit", rpm:"libpoppler-qt5-1-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit-debuginfo", rpm:"libpoppler-qt5-1-32bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-32bit", rpm:"libpoppler126-32bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit", rpm:"libpoppler-qt5-1-64bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-64bit-debuginfo", rpm:"libpoppler126-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-64bit-debuginfo", rpm:"libpoppler-qt5-1-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126-64bit", rpm:"libpoppler126-64bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit-debuginfo", rpm:"libpoppler-cpp0-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-64bit", rpm:"libpoppler-cpp0-64bit~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit-debuginfo", rpm:"libpoppler-glib8-64bit-debuginfo~23.01.0~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-64bit", rpm:"libpoppler-glib8-64bit~23.01.0~150500.3.11.1##", rls:"openSUSELeap15.5"))) {
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