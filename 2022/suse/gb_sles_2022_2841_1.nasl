# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2841.1");
  script_cve_id("CVE-2020-14343", "CVE-2020-1747");
  script_tag(name:"creation_date", value:"2022-08-19 04:39:30 +0000 (Fri, 19 Aug 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-30 13:59:36 +0000 (Mon, 30 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2841-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2841-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222841-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-PyYAML' package(s) announced via the SUSE-SU-2022:2841-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-PyYAML fixes the following issues:

CVE-2020-1747: Fixed an arbitrary code execution issue when parsing an
 untrusted YAML file with the default loader (bsc#1165439).

CVE-2020-14343: Completed the fix for CVE-2020-1747 (bsc#1174514).");

  script_tag(name:"affected", value:"'python-PyYAML' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Public Cloud 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-PyYAML", rpm:"python3-PyYAML~5.1.2~150000.3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML-debuginfo", rpm:"python-PyYAML-debuginfo~5.1.2~150000.3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML-debugsource", rpm:"python-PyYAML-debugsource~5.1.2~150000.3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-PyYAML", rpm:"python2-PyYAML~5.1.2~150000.3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-PyYAML-debuginfo", rpm:"python2-PyYAML-debuginfo~5.1.2~150000.3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-PyYAML-debuginfo", rpm:"python3-PyYAML-debuginfo~5.1.2~150000.3.6.1", rls:"SLES15.0"))) {
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
