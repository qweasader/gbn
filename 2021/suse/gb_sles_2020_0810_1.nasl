# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0810.1");
  script_cve_id("CVE-2018-11805", "CVE-2020-1930", "CVE-2020-1931");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-01 02:42:37 +0000 (Sat, 01 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0810-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0810-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200810-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spamassassin' package(s) announced via the SUSE-SU-2020:0810-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for spamassassin fixes the following issues:

CVE-2018-11805: Fixed an issue with delimiter handling in rule files
 related to is_regexp_valid() (bsc#1118987).

CVE-2020-1930: Fixed an issue with rule configuration (.cf) files which
 can be configured to run system commands (bsc#1162197).

CVE-2020-1931: Fixed an issue with rule configuration (.cf) files which
 can be configured to run system commands with warnings (bsc#1162200).");

  script_tag(name:"affected", value:"'spamassassin' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~44.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~44.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debuginfo", rpm:"spamassassin-debuginfo~3.4.2~44.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debugsource", rpm:"spamassassin-debugsource~3.4.2~44.8.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~44.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~44.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debuginfo", rpm:"spamassassin-debuginfo~3.4.2~44.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debugsource", rpm:"spamassassin-debugsource~3.4.2~44.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~44.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~44.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debuginfo", rpm:"spamassassin-debuginfo~3.4.2~44.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debugsource", rpm:"spamassassin-debugsource~3.4.2~44.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~44.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~44.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debuginfo", rpm:"spamassassin-debuginfo~3.4.2~44.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debugsource", rpm:"spamassassin-debugsource~3.4.2~44.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~44.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~44.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debuginfo", rpm:"spamassassin-debuginfo~3.4.2~44.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debugsource", rpm:"spamassassin-debugsource~3.4.2~44.8.1", rls:"SLES12.0SP5"))) {
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
