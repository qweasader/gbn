# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0112.1");
  script_cve_id("CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-13 13:14:32 +0000 (Fri, 13 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0112-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0112-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170112-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2017:0112-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:
- Fix a potential assertion failure that could have been triggered by a
 malformed response to an ANY query, thereby facilitating a
 denial-of-service attack. [CVE-2016-9131, bsc#1018700, bsc#1018699]
- Fix a potential assertion failure that could have been triggered by
 responding to a query with inconsistent DNSSEC information, thereby
 facilitating a denial-of-service attack. [CVE-2016-9147, bsc#1018701,
 bsc#1018699]
- Fix potential assertion failure that could have been triggered by DNS
 responses that contain unusually-formed DS resource records,
 facilitating a denial-of-service attack. [CVE-2016-9444, bsc#1018702,
 bsc#1018699]");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.6P1~0.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.6P1~0.36.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.9.6P1~0.36.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.9.6P1~0.36.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.9.6P1~0.36.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.6P1~0.36.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.6P1~0.36.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-x86", rpm:"bind-libs-x86~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.6P1~0.36.1", rls:"SLES11.0SP4"))) {
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
