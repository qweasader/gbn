# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1342");
  script_cve_id("CVE-2016-2381");
  script_tag(name:"creation_date", value:"2021-02-22 08:39:51 +0000 (Mon, 22 Feb 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 13:20:00 +0000 (Thu, 10 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for perl (EulerOS-SA-2021-1342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1342");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1342");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'perl' package(s) announced via the EulerOS-SA-2021-1342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Perl might allow context-dependent attackers to bypass the taint protection mechanism in a child process via duplicate environment variables in envp.(CVE-2016-2381)");

  script_tag(name:"affected", value:"'perl' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.16.3~285.h9", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.16.3~285.h9", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.16.3~285.h9", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.16.3~285.h9", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-macros", rpm:"perl-macros~5.16.3~285.h9", rls:"EULEROS-2.0SP2"))) {
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
