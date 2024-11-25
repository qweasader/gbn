# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856708");
  script_version("2024-11-13T05:05:39+0000");
  script_cve_id("CVE-2024-4131", "CVE-2024-41311");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-11 16:15:14 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-09 05:00:36 +0000 (Sat, 09 Nov 2024)");
  script_name("openSUSE: Security Advisory for libheif (SUSE-SU-2024:3960-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3960-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KPACBCSOHMOEYEZ2DMHSNEENN3KPC3T6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheif'
  package(s) announced via the SUSE-SU-2024:3960-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libheif fixes the following issues:

  * CVE-2024-41311: Fixed out-of-bounds read and write in ImageOverlay:parse()
      due to decoding a heif file containing an overlay image with forged offsets
      (bsc#1231714).");

  script_tag(name:"affected", value:"'libheif' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-debugsource", rpm:"libheif-debugsource~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif-debuginfo", rpm:"gdk-pixbuf-loader-libheif-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-debuginfo", rpm:"libheif1-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif", rpm:"gdk-pixbuf-loader-libheif~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-32bit", rpm:"libheif1-32bit~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-32bit-debuginfo", rpm:"libheif1-32bit-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-debugsource", rpm:"libheif-debugsource~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif-debuginfo", rpm:"gdk-pixbuf-loader-libheif-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-debuginfo", rpm:"libheif1-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif", rpm:"gdk-pixbuf-loader-libheif~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-32bit", rpm:"libheif1-32bit~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-32bit-debuginfo", rpm:"libheif1-32bit-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-64bit", rpm:"libheif1-64bit~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-64bit-debuginfo", rpm:"libheif1-64bit-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-debugsource", rpm:"libheif-debugsource~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif-debuginfo", rpm:"gdk-pixbuf-loader-libheif-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-debuginfo", rpm:"libheif1-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif", rpm:"gdk-pixbuf-loader-libheif~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-32bit", rpm:"libheif1-32bit~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1-32bit-debuginfo", rpm:"libheif1-32bit-debuginfo~1.12.0~150400.3.14.1", rls:"openSUSELeap15.5"))) {
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
