# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0049");
  script_cve_id("CVE-2020-25459");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-28 17:06:16 +0000 (Tue, 28 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2021-0049)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0049");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0049.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27444");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RKSUG2OZN3Y2FQVQ55HP5MZIQZXZ5OD6/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-10/msg00032.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crmsh' package(s) announced via the MGASA-2021-0049 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The crm configure and hb_report commands failed to sanitize sensitive
information by default (bsc#1163581).

An issue was discovered in ClusterLabs crmsh through 4.2.1. Local attackers
able to call 'crm history' (when 'crm' is run) were able to execute commands
via shell code injection to the crm history commandline, potentially allowing
escalation of privileges (CVE-2020-25459).

The crmsh package has been updated to the latest git snapshot and patched for
CVE-2020-25459, fixing these issues and several others.");

  script_tag(name:"affected", value:"'crmsh' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"crmsh", rpm:"crmsh~4.2.0~0.39d42c2.1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crmsh-scripts", rpm:"crmsh-scripts~4.2.0~0.39d42c2.1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crmsh-test", rpm:"crmsh-test~4.2.0~0.39d42c2.1.1.mga7", rls:"MAGEIA7"))) {
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
