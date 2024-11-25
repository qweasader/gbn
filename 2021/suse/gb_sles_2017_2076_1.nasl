# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2076.1");
  script_cve_id("CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-03 13:11:18 +0000 (Mon, 03 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2076-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172076-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses' package(s) announced via the SUSE-SU-2017:2076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ncurses fixes the following issues:
Security issues fixed:
- CVE-2017-11112: Illegal address access in append_acs. (bsc#1047964)
- CVE-2017-11113: Dereferencing NULL pointer in _nc_parse_entry.
 (bsc#1047965)
- CVE-2017-10684, CVE-2017-10685: Add modified upstream fix from ncurses
 6.0 to avoid broken termcap format (bsc#1046853, bsc#1046858,
 bsc#1049344)");

  script_tag(name:"affected", value:"'ncurses' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libncurses5-32bit", rpm:"libncurses5-32bit~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses5", rpm:"libncurses5~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses5-x86", rpm:"libncurses5-x86~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6-32bit", rpm:"libncurses6-32bit~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6", rpm:"libncurses6~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6-x86", rpm:"libncurses6-x86~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-devel-32bit", rpm:"ncurses-devel-32bit~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-devel", rpm:"ncurses-devel~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-utils", rpm:"ncurses-utils~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tack", rpm:"tack~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"terminfo", rpm:"terminfo~5.6~93.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"terminfo-base", rpm:"terminfo-base~5.6~93.6.1", rls:"SLES11.0SP4"))) {
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
