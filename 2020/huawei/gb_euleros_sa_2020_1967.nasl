# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1967");
  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_tag(name:"creation_date", value:"2020-09-08 08:07:45 +0000 (Tue, 08 Sep 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for perl (EulerOS-SA-2020-1967)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1967");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1967");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'perl' package(s) announced via the EulerOS-SA-2020-1967 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Perl before 5.30.3 has an integer overflow related to mishandling of a 'PL_regkind[OP(n)] == NOTHING' situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction injection.(CVE-2020-10878)

regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of recursive S_study_chunk calls.(CVE-2020-12723)

Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular expression quantifiers have an integer overflow.(CVE-2020-10543)");

  script_tag(name:"affected", value:"'perl' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.16.3~292.h13", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~292.h13", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.16.3~292.h13", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-macros", rpm:"perl-macros~5.16.3~292.h13", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
