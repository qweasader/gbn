# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3458.1");
  script_cve_id("CVE-2021-3618");
  script_tag(name:"creation_date", value:"2022-09-29 12:50:56 +0000 (Thu, 29 Sep 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 20:46:57 +0000 (Mon, 04 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3458-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223458-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vsftpd' package(s) announced via the SUSE-SU-2022:3458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vsftpd fixes the following issues:

CVE-2021-3618: Enforced security checks against ALPACA attack (PM-3322,
 jsc#SLE-23895, bsc#1187686, bsc#1187678).

Added hardening to systemd services (bsc#1181400).

Bugfixes:
Fixed a seccomp failure in FIPS mode when SSL was enabled (bsc#1052900).

Allowed wait4() to be called so that the broker can wait for its child
 processes (bsc#1021387).

Fixed hang when using seccomp and syslog (bsc#971784).

Allowed sendto() syscall when /dev/log support is enabled (bsc#786024).");

  script_tag(name:"affected", value:"'vsftpd' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~3.0.5~150000.7.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vsftpd-debuginfo", rpm:"vsftpd-debuginfo~3.0.5~150000.7.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vsftpd-debugsource", rpm:"vsftpd-debugsource~3.0.5~150000.7.19.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~3.0.5~150000.7.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vsftpd-debuginfo", rpm:"vsftpd-debuginfo~3.0.5~150000.7.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vsftpd-debugsource", rpm:"vsftpd-debugsource~3.0.5~150000.7.19.1", rls:"SLES15.0SP1"))) {
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
