# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856410");
  script_version("2024-09-12T07:59:53+0000");
  script_cve_id("CVE-2024-40724");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 20:15:57 +0000 (Wed, 07 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-04 04:00:32 +0000 (Wed, 04 Sep 2024)");
  script_name("openSUSE: Security Advisory for libqt5 (SUSE-SU-2024:3078-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3078-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZU245ZX6KRTPG23W32W35M6ZMN3KI5YA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5'
  package(s) announced via the SUSE-SU-2024:3078-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtquick3d fixes the following issues:

  * CVE-2024-40724: Fixed heap-based buffer overflow in the PLY importer class
      in assimp (bsc#1228199)

  Other fixes: \- Fix progressive anti-aliasing, which doesn't work if any object
  in the scene used a PrincipledMaterial \- Skip processing unknown uniforms, such
  as those that are vendor specific:

  ##");

  script_tag(name:"affected", value:"'libqt5' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5Quick3D5-debuginfo", rpm:"libQt5Quick3D5-debuginfo~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-devel", rpm:"libqt5-qtquick3d-devel~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-debuginfo", rpm:"libqt5-qtquick3d-debuginfo~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-examples", rpm:"libqt5-qtquick3d-examples~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-imports", rpm:"libqt5-qtquick3d-imports~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Quick3D5", rpm:"libQt5Quick3D5~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Quick3DAssetImport5", rpm:"libQt5Quick3DAssetImport5~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-examples-debuginfo", rpm:"libqt5-qtquick3d-examples-debuginfo~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-private-headers-devel", rpm:"libqt5-qtquick3d-private-headers-devel~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-tools", rpm:"libqt5-qtquick3d-tools~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-imports-debuginfo", rpm:"libqt5-qtquick3d-imports-debuginfo~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-tools-debuginfo", rpm:"libqt5-qtquick3d-tools-debuginfo~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Quick3DAssetImport5-debuginfo", rpm:"libQt5Quick3DAssetImport5-debuginfo~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-debugsource", rpm:"libqt5-qtquick3d-debugsource~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
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