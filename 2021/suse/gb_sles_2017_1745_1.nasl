# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1745.1");
  script_cve_id("CVE-2012-6706");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-06 18:51:30 +0000 (Thu, 06 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1745-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1745-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171745-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrar' package(s) announced via the SUSE-SU-2017:1745-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unrar fixes the following issues:
- CVE-2012-6706: decoding malicious RAR files could have lead to memory
 corruption or code execution. (bsc#1045315).");

  script_tag(name:"affected", value:"'unrar' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP 12, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE OpenStack Cloud 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.0.14~3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.0.14~3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.0.14~3.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.0.14~3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.0.14~3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.0.14~3.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.0.14~3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.0.14~3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.0.14~3.1", rls:"SLES12.0SP2"))) {
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
