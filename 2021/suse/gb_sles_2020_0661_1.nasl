# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0661.1");
  script_cve_id("CVE-2019-12523", "CVE-2019-12526", "CVE-2019-12528", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679", "CVE-2020-8449", "CVE-2020-8450", "CVE-2020-8517");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 14:35:04 +0000 (Thu, 06 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0661-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200661-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the SUSE-SU-2020:0661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid fixes the following issues:
CVE-2019-12528: Fixed an information disclosure flaw in the FTP gateway
 (bsc#1162689).

CVE-2019-12526: Fixed potential remote code execution during URN
 processing (bsc#1156326).

CVE-2019-12523,CVE-2019-18676: Fixed multiple improper validations in
 URI processing (bsc#1156329).

CVE-2019-18677: Fixed Cross-Site Request Forgery in HTTP Request
 processing (bsc#1156328).

CVE-2019-18678: Fixed incorrect message parsing which could have led to
 HTTP request splitting issue (bsc#1156323).

CVE-2019-18679: Fixed information disclosure when processing HTTP Digest
 Authentication (bsc#1156324).

CVE-2020-8449: Fixed a buffer overflow when squid is acting as
 reverse-proxy (bsc#1162687).

CVE-2020-8450: Fixed a buffer overflow when squid is acting as
 reverse-proxy (bsc#1162687).

CVE-2020-8517: Fixed a buffer overflow in ext_lm_group_acl when
 processing NTLM Authentication credentials (bsc#1162691).");

  script_tag(name:"affected", value:"'squid' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.21~26.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.5.21~26.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~3.5.21~26.20.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.21~26.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.5.21~26.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~3.5.21~26.20.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.21~26.20.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.5.21~26.20.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~3.5.21~26.20.1", rls:"SLES12.0SP4"))) {
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
