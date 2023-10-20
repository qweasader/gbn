# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2978.1");
  script_cve_id("CVE-2014-9636", "CVE-2014-9913", "CVE-2015-7696", "CVE-2015-7697", "CVE-2016-9844", "CVE-2018-1000035");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2978-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2978-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182978-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the SUSE-SU-2018:2978-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unzip fixes the following security issues:
CVE-2014-9913: Specially crafted zip files could trigger invalid memory
 writes possibly resulting in DoS or corruption (bsc#1013993)

CVE-2015-7696: Specially crafted zip files with password protection
 could trigger a crash and lead to denial of service (bsc#950110)

CVE-2015-7697: Specially crafted zip files could trigger an endless loop
 and lead to denial of service (bsc#950111)

CVE-2016-9844: Specially crafted zip files could trigger invalid memory
 writes possibly resulting in DoS or corruption (bsc#1013992)

CVE-2018-1000035: Prevent heap-based buffer overflow in the processing
 of password-protected archives that allowed an attacker to perform a
 denial of service or to possibly achieve code execution (bsc#1080074).

CVE-2014-9636: Prevent denial of service (out-of-bounds read or write
 and crash) via an extra field with an uncompressed size smaller than the
 compressed field size in a zip archive that advertises STORED method
 compression (bsc#914442).

This non-security issue was fixed:

+- Allow processing of Windows zip64 archives (Windows archivers set
 total_disks field to 0 but per standard, valid values are 1 and higher)
 (bnc#910683)");

  script_tag(name:"affected", value:"'unzip' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.00~33.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unzip-debuginfo", rpm:"unzip-debuginfo~6.00~33.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unzip-debugsource", rpm:"unzip-debugsource~6.00~33.8.1", rls:"SLES12.0SP3"))) {
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
