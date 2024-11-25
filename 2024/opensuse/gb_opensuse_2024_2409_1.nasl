# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856321");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2023-44488", "CVE-2023-6349", "CVE-2024-5197");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-03 20:57:51 +0000 (Tue, 03 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:39 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for libvpx (SUSE-SU-2024:2409-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2409-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DK6ZXP64L4GJLPACUJBDLIAPI3F6Z25P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvpx'
  package(s) announced via the SUSE-SU-2024:2409-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvpx fixes the following issues:

  * CVE-2024-5197: Fixed integer overflow when calling vpx_img_alloc() or
      vpx_img_wrap() with large parameters (bsc#1225879).

  * CVE-2023-6349: Fixed heap overflow when encoding a frame that has larger
      dimensions than the originally configured size (bsc#1225403).

  * CVE-2023-44488: Fixed heap buffer overflow in vp8 encoding (bsc#1216879).");

  script_tag(name:"affected", value:"'libvpx' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-debuginfo", rpm:"libvpx7-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7", rpm:"libvpx7~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools", rpm:"vpx-tools~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools-debuginfo", rpm:"vpx-tools-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-debugsource", rpm:"libvpx-debugsource~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-32bit-debuginfo", rpm:"libvpx7-32bit-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-32bit", rpm:"libvpx7-32bit~1.11.0~150400.3.7.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-debuginfo", rpm:"libvpx7-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7", rpm:"libvpx7~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools", rpm:"vpx-tools~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools-debuginfo", rpm:"vpx-tools-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-debugsource", rpm:"libvpx-debugsource~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-32bit-debuginfo", rpm:"libvpx7-32bit-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-32bit", rpm:"libvpx7-32bit~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-64bit", rpm:"libvpx7-64bit~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-64bit-debuginfo", rpm:"libvpx7-64bit-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-debuginfo", rpm:"libvpx7-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7", rpm:"libvpx7~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools", rpm:"vpx-tools~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools-debuginfo", rpm:"vpx-tools-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-debugsource", rpm:"libvpx-debugsource~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-32bit-debuginfo", rpm:"libvpx7-32bit-debuginfo~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7-32bit", rpm:"libvpx7-32bit~1.11.0~150400.3.7.1", rls:"openSUSELeap15.5"))) {
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
