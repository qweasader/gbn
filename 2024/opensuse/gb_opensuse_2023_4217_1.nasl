# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833727");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-45853");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-19 12:44:29 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:48:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for zlib (SUSE-SU-2023:4217-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4217-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IM6RQLZ4ZUUBOCSIEVVTDLVGX2USJCNU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib'
  package(s) announced via the SUSE-SU-2023:4217-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zlib fixes the following issues:

  * CVE-2023-45853: Fixed an integer overflow that would lead to a buffer
      overflow in the minizip subcomponent (bsc#1216378).

  ##");

  script_tag(name:"affected", value:"'zlib' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minizip-devel", rpm:"minizip-devel~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static", rpm:"zlib-devel-static~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel", rpm:"zlib-devel~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-debuginfo", rpm:"libz1-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1", rpm:"libz1~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-debugsource", rpm:"zlib-debugsource~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-debuginfo", rpm:"libminizip1-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit-debuginfo", rpm:"libz1-32bit-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-32bit", rpm:"zlib-devel-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit", rpm:"libminizip1-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static-32bit", rpm:"zlib-devel-static-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit", rpm:"libz1-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit-debuginfo", rpm:"libminizip1-32bit-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minizip-devel", rpm:"minizip-devel~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static", rpm:"zlib-devel-static~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel", rpm:"zlib-devel~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-debuginfo", rpm:"libz1-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1", rpm:"libz1~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-debugsource", rpm:"zlib-debugsource~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-debuginfo", rpm:"libminizip1-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit-debuginfo", rpm:"libz1-32bit-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-32bit", rpm:"zlib-devel-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit", rpm:"libminizip1-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static-32bit", rpm:"zlib-devel-static-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit", rpm:"libz1-32bit~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit-debuginfo", rpm:"libminizip1-32bit-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libz1", rpm:"libz1~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel", rpm:"zlib-devel~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-debugsource", rpm:"zlib-debugsource~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-debuginfo", rpm:"libz1-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libz1", rpm:"libz1~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel", rpm:"zlib-devel~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-debugsource", rpm:"zlib-debugsource~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-debuginfo", rpm:"libz1-debuginfo~1.2.11~150000.3.48.1", rls:"openSUSELeapMicro5.4"))) {
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