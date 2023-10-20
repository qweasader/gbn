# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1059.1");
  script_cve_id("CVE-2022-22934", "CVE-2022-22935", "CVE-2022-22936", "CVE-2022-22941");
  script_tag(name:"creation_date", value:"2022-03-31 04:11:26 +0000 (Thu, 31 Mar 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-06 20:25:00 +0000 (Wed, 06 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1059-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221059-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2022:1059-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

CVE-2022-22935: Sign authentication replies to prevent MiTM (bsc#1197417)

CVE-2022-22934: Sign pillar data to prevent MiTM attacks. (bsc#1197417)

CVE-2022-22936: Prevent job and fileserver replays (bsc#1197417)

CVE-2022-22941: Fixed targeting bug, especially visible when using
 syndic and user auth. (bsc#1197417)");

  script_tag(name:"affected", value:"'salt' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Server Applications 15-SP3, SUSE Linux Enterprise Module for Transactional Server 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-transactional-update", rpm:"salt-transactional-update~3002.2~150300.53.10.1", rls:"SLES15.0SP3"))) {
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
