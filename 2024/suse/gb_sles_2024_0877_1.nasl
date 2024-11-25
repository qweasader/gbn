# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0877.1");
  script_cve_id("CVE-2023-42465");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2024-05-09T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-05-09 05:05:43 +0000 (Thu, 09 May 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-03 17:40:23 +0000 (Wed, 03 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0877-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0877-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240877-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2024:0877-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sudo fixes the following issues:

CVE-2023-42465: Fixed issues introduced by first patches (bsc#1221151, bsc#1221134).");

  script_tag(name:"affected", value:"'sudo' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.9.9~150400.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.9.9~150400.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debugsource", rpm:"sudo-debugsource~1.9.9~150400.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.9.9~150400.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-plugin-python", rpm:"sudo-plugin-python~1.9.9~150400.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-plugin-python-debuginfo", rpm:"sudo-plugin-python-debuginfo~1.9.9~150400.4.36.1", rls:"SLES15.0SP4"))) {
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
