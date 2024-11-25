# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856550");
  script_version("2024-10-16T08:00:45+0000");
  script_cve_id("CVE-2024-45490", "CVE-2024-45491", "CVE-2024-45492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-16 08:00:45 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-10-10 04:00:31 +0000 (Thu, 10 Oct 2024)");
  script_name("openSUSE: Security Advisory for mozjs78 (SUSE-SU-2024:3554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3554-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NII5WWMANSN5NYNMNOK7LJ2P5FT7TW5X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozjs78'
  package(s) announced via the SUSE-SU-2024:3554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozjs78 fixes the following issues:

  * CVE-2024-45490: Fixed negative len for XML_ParseBuffer in embedded expat
      (bnc#1230036)

  * CVE-2024-45491: Fixed integer overflow in dtdCopy in embedded expat
      (bnc#1230037)

  * CVE-2024-45492: Fixed integer overflow in function nextScaffoldPart in
      embedded expat (bnc#1230038)");

  script_tag(name:"affected", value:"'mozjs78' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-78-0-debuginfo", rpm:"libmozjs-78-0-debuginfo~78.15.0~150400.3.6.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-78-0", rpm:"libmozjs-78-0~78.15.0~150400.3.6.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-debuginfo", rpm:"mozjs78-debuginfo~78.15.0~150400.3.6.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78", rpm:"mozjs78~78.15.0~150400.3.6.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-debugsource", rpm:"mozjs78-debugsource~78.15.0~150400.3.6.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-devel", rpm:"mozjs78-devel~78.15.0~150400.3.6.2", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-78-0-debuginfo", rpm:"libmozjs-78-0-debuginfo~78.15.0~150400.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-78-0", rpm:"libmozjs-78-0~78.15.0~150400.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-debuginfo", rpm:"mozjs78-debuginfo~78.15.0~150400.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78", rpm:"mozjs78~78.15.0~150400.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-debugsource", rpm:"mozjs78-debugsource~78.15.0~150400.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-devel", rpm:"mozjs78-devel~78.15.0~150400.3.6.2", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-78-0-debuginfo", rpm:"libmozjs-78-0-debuginfo~78.15.0~150400.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-78-0", rpm:"libmozjs-78-0~78.15.0~150400.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-debuginfo", rpm:"mozjs78-debuginfo~78.15.0~150400.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78", rpm:"mozjs78~78.15.0~150400.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-debugsource", rpm:"mozjs78-debugsource~78.15.0~150400.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78-devel", rpm:"mozjs78-devel~78.15.0~150400.3.6.2", rls:"openSUSELeap15.5"))) {
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