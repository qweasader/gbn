# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3250.1");
  script_cve_id("CVE-2016-9957", "CVE-2016-9958", "CVE-2016-9959", "CVE-2016-9960", "CVE-2016-9961");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3250-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3250-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163250-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgme' package(s) announced via the SUSE-SU-2016:3250-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgme fixes the following issues:
- CVE-2016-9957, CVE-2016-9958, CVE-2016-9959, CVE-2016-9960,
 CVE-2016-9961: Various issues were fixed in the handling of SPC music
 files that could have been exploited for gaining privileges of desktop
 users. [bsc#1015941]");

  script_tag(name:"affected", value:"'libgme' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libgme-debugsource", rpm:"libgme-debugsource~0.6.0~5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgme0", rpm:"libgme0~0.6.0~5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgme0-debuginfo", rpm:"libgme0-debuginfo~0.6.0~5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libgme-debugsource", rpm:"libgme-debugsource~0.6.0~5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgme0", rpm:"libgme0~0.6.0~5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgme0-debuginfo", rpm:"libgme0-debuginfo~0.6.0~5.1", rls:"SLES12.0SP2"))) {
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
