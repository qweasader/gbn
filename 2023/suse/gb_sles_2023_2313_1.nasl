# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2313.1");
  script_cve_id("CVE-2023-31124", "CVE-2023-31130", "CVE-2023-31147", "CVE-2023-32067");
  script_tag(name:"creation_date", value:"2023-05-31 04:21:14 +0000 (Wed, 31 May 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:09:00 +0000 (Thu, 01 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2313-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2313-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232313-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'c-ares' package(s) announced via the SUSE-SU-2023:2313-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for c-ares fixes the following issues:
Update to version 1.19.1:

CVE-2023-32067: 0-byte UDP payload causes Denial of Service (bsc#1211604)
CVE-2023-31147: Insufficient randomness in generation of DNS query IDs (bsc#1211605)
CVE-2023-31130: Buffer Underwrite in ares_inet_net_pton() (bsc#1211606)
CVE-2023-31124: AutoTools does not set CARES_RANDOM_FILE during cross compilation (bsc#1211607)
Fix uninitialized memory warning in test ares_getaddrinfo() should allow a port of 0 Fix memory leak in ares_send() on error Fix comment style in ares_data.h Fix typo in ares_init_options.3 Sync ax_pthread.m4 with upstream Sync ax_cxx_compile_stdcxx_11.m4 with upstream to fix uclibc support");

  script_tag(name:"affected", value:"'c-ares' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.19.1~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.19.1~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.19.1~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.19.1~150000.3.23.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.19.1~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.19.1~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.19.1~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.19.1~150000.3.23.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.19.1~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.19.1~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.19.1~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.19.1~150000.3.23.1", rls:"SLES15.0SP3"))) {
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
