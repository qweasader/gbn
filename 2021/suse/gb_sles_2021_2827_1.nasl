# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2827.1");
  script_cve_id("CVE-2021-3712");
  script_tag(name:"creation_date", value:"2021-08-25 02:24:18 +0000 (Wed, 25 Aug 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 16:48:54 +0000 (Tue, 31 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2827-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2827-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212827-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_0_0' package(s) announced via the SUSE-SU-2021:2827-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_0_0 fixes the following issues:

CVE-2021-3712: a bug in the code for printing certificate details could
 lead to a buffer overrun that a malicious actor could exploit to crash
 the application, causing a denial-of-service attack. [bsc#1189521]");

  script_tag(name:"affected", value:"'openssl-1_0_0' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~3.40.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~3.40.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~3.40.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debuginfo", rpm:"openssl-1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debugsource", rpm:"openssl-1_0_0-debugsource~1.0.2p~3.40.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10", rpm:"libopenssl10~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10-debuginfo", rpm:"libopenssl10-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debuginfo", rpm:"openssl-1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debugsource", rpm:"openssl-1_0_0-debugsource~1.0.2p~3.40.2", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~3.40.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~3.40.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~3.40.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debuginfo", rpm:"openssl-1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debugsource", rpm:"openssl-1_0_0-debugsource~1.0.2p~3.40.2", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~3.40.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~3.40.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~3.40.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debuginfo", rpm:"openssl-1_0_0-debuginfo~1.0.2p~3.40.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debugsource", rpm:"openssl-1_0_0-debugsource~1.0.2p~3.40.2", rls:"SLES15.0SP1"))) {
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
