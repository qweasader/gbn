# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2798.1");
  script_cve_id("CVE-2020-24330");
  script_tag(name:"creation_date", value:"2022-08-15 04:45:26 +0000 (Mon, 15 Aug 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-05 04:15:00 +0000 (Thu, 05 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2798-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2798-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222798-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trousers' package(s) announced via the SUSE-SU-2022:2798-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for trousers fixes the following issues:

CVE-2020-24330: Fixed a potential tss user to root privilege escalation
 issue (bsc#1164472).");

  script_tag(name:"affected", value:"'trousers' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtspi1", rpm:"libtspi1~0.3.14~150000.3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtspi1-debuginfo", rpm:"libtspi1-debuginfo~0.3.14~150000.3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trousers", rpm:"trousers~0.3.14~150000.3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trousers-debuginfo", rpm:"trousers-debuginfo~0.3.14~150000.3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trousers-debugsource", rpm:"trousers-debugsource~0.3.14~150000.3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trousers-devel", rpm:"trousers-devel~0.3.14~150000.3.3.1", rls:"SLES15.0"))) {
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
