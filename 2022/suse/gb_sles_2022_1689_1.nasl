# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1689.1");
  script_cve_id("CVE-2021-43565", "CVE-2022-23648", "CVE-2022-24769", "CVE-2022-27191");
  script_tag(name:"creation_date", value:"2022-05-17 04:28:29 +0000 (Tue, 17 May 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-25 17:15:25 +0000 (Fri, 25 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1689-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1689-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221689-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker' package(s) announced via the SUSE-SU-2022:1689-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker fixes the following issues:

CVE-2022-24769: Fixed incorrect default inheritable capabilities
 (bsc#1197517).

CVE-2022-23648: Fixed directory traversal issue (bsc#1196441).

CVE-2022-27191: Fixed a crash in a golang.org/x/crypto/ssh server
 (bsc#1197284).

CVE-2021-43565: Fixed a panic in golang.org/x/crypto by empty plaintext
 packet (bsc#1193930).");

  script_tag(name:"affected", value:"'containerd, docker' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Micro 5.0, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Containers 15-SP3, SUSE Linux Enterprise Module for Containers 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.5.11~150000.68.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.5.11~150000.68.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.14_ce~150000.163.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.14_ce~150000.163.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.14_ce~150000.163.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.14_ce~150000.163.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.5.11~150000.68.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.14_ce~150000.163.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.14_ce~150000.163.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.14_ce~150000.163.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.5.11~150000.68.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.5.11~150000.68.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.14_ce~150000.163.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.14_ce~150000.163.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.14_ce~150000.163.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.5.11~150000.68.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.5.11~150000.68.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.14_ce~150000.163.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.14_ce~150000.163.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.14_ce~150000.163.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.5.11~150000.68.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.5.11~150000.68.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.14_ce~150000.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.14_ce~150000.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.14_ce~150000.163.1", rls:"SLES15.0SP2"))) {
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
