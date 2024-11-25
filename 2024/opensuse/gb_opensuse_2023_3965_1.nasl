# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833624");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-43788", "CVE-2023-43789");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 18:05:37 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libXpm (SUSE-SU-2023:3965-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3965-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G5GB4YZJX63JNFUYP4N5R4EU3I2T6IL2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXpm'
  package(s) announced via the SUSE-SU-2023:3965-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libXpm fixes the following issues:

  * CVE-2023-43788: Fixed an out of bounds read when creating an image
      (bsc#1215686).

  * CVE-2023-43789: Fixed an out of bounds read when parsing an XPM file with a
      corrupted colormap (bsc#1215687).

  ##");

  script_tag(name:"affected", value:"'libXpm' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-debuginfo", rpm:"libXpm4-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools", rpm:"libXpm-tools~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4", rpm:"libXpm4~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools-debuginfo", rpm:"libXpm-tools-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel", rpm:"libXpm-devel~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-debugsource", rpm:"libXpm-debugsource~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit-debuginfo", rpm:"libXpm4-32bit-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel-32bit", rpm:"libXpm-devel-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit", rpm:"libXpm4-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-debuginfo", rpm:"libXpm4-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools", rpm:"libXpm-tools~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4", rpm:"libXpm4~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools-debuginfo", rpm:"libXpm-tools-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel", rpm:"libXpm-devel~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-debugsource", rpm:"libXpm-debugsource~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit-debuginfo", rpm:"libXpm4-32bit-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel-32bit", rpm:"libXpm-devel-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit", rpm:"libXpm4-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-debuginfo", rpm:"libXpm4-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools", rpm:"libXpm-tools~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4", rpm:"libXpm4~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools-debuginfo", rpm:"libXpm-tools-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel", rpm:"libXpm-devel~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-debugsource", rpm:"libXpm-debugsource~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit-debuginfo", rpm:"libXpm4-32bit-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel-32bit", rpm:"libXpm-devel-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit", rpm:"libXpm4-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-debuginfo", rpm:"libXpm4-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools", rpm:"libXpm-tools~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4", rpm:"libXpm4~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-tools-debuginfo", rpm:"libXpm-tools-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel", rpm:"libXpm-devel~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-debugsource", rpm:"libXpm-debugsource~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit-debuginfo", rpm:"libXpm4-32bit-debuginfo~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel-32bit", rpm:"libXpm-devel-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm4-32bit", rpm:"libXpm4-32bit~3.5.12~150000.3.10.1", rls:"openSUSELeap15.5"))) {
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