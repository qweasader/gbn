# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1379.1");
  script_cve_id("CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-5836", "CVE-2017-6440", "CVE-2017-7982");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-02 10:15:00 +0000 (Thu, 02 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1379-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1379-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171379-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libplist' package(s) announced via the SUSE-SU-2017:1379-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libplist fixes the following issues:
- CVE-2017-5209: The base64decode function in libplist allowed attackers
 to obtain sensitive information from process memory or cause a denial of
 service (buffer over-read) via split encoded Apple Property List data
 (bsc#1019531).
- CVE-2017-5545: The main function in plistutil.c in libimobiledevice
 libplist allowed attackers to obtain sensitive information from process
 memory or cause a denial of service (buffer over-read) via Apple
 Property List data that is too short. (bsc#1021610).
- CVE-2017-5836: A type inconsistency in bplist.c was fixed. (bsc#1023807)
- CVE-2017-5835: A memory allocation error leading to DoS was fixed.
 (bsc#1023822)
- CVE-2017-5834: A heap-buffer overflow in parse_dict_node was fixed.
 (bsc#1023848)
- CVE-2017-6440: Ensure that sanity checks work on 32-bit platforms.
 (bsc#1029631)
- CVE-2017-7982: Add some safety checks, backported from upstream
 (bsc#1035312).
- CVE-2017-5836: A maliciously crafted file could cause the application to
 crash. (bsc#1023807).
- CVE-2017-5835: Malicious crafted file could cause libplist to allocate
 large amounts of memory and consume lots of CPU (bsc#1023822)
- CVE-2017-5834: Maliciou crafted file could cause a heap buffer overflow
 or segmentation fault (bsc#1023848)");

  script_tag(name:"affected", value:"'libplist' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libplist-debugsource", rpm:"libplist-debugsource~1.12~19.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist3", rpm:"libplist3~1.12~19.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist3-debuginfo", rpm:"libplist3-debuginfo~1.12~19.1", rls:"SLES12.0SP2"))) {
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
