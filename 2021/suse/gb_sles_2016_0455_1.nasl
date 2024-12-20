# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0455.1");
  script_cve_id("CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-03 19:52:30 +0000 (Thu, 03 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0455-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160455-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libnettle' package(s) announced via the SUSE-SU-2016:0455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libnettle fixes the following security issues:
- CVE-2015-8803: Fixed miscomputation bugs in secp-256r1 modulo functions.
 (bsc#964845)
- CVE-2015-8804: Fixed carry folding bug in x86_64 ecc_384_modp.
 (bsc#964847)
- CVE-2015-8805: Fixed miscomputation bugs in secp-256r1 modulo functions.
 (bsc#964849)");

  script_tag(name:"affected", value:"'libnettle' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2", rpm:"libhogweed2~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2-32bit", rpm:"libhogweed2-32bit~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2-debuginfo", rpm:"libhogweed2-debuginfo~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2-debuginfo-32bit", rpm:"libhogweed2-debuginfo-32bit~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle-debugsource", rpm:"libnettle-debugsource~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4", rpm:"libnettle4~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4-32bit", rpm:"libnettle4-32bit~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4-debuginfo", rpm:"libnettle4-debuginfo~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4-debuginfo-32bit", rpm:"libnettle4-debuginfo-32bit~2.7.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2", rpm:"libhogweed2~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2-32bit", rpm:"libhogweed2-32bit~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2-debuginfo", rpm:"libhogweed2-debuginfo~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2-debuginfo-32bit", rpm:"libhogweed2-debuginfo-32bit~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle-debugsource", rpm:"libnettle-debugsource~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4", rpm:"libnettle4~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4-32bit", rpm:"libnettle4-32bit~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4-debuginfo", rpm:"libnettle4-debuginfo~2.7.1~9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4-debuginfo-32bit", rpm:"libnettle4-debuginfo-32bit~2.7.1~9.1", rls:"SLES12.0SP1"))) {
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
