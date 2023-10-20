# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0617.1");
  script_cve_id("CVE-2020-5208");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 03:15:00 +0000 (Thu, 01 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0617-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200617-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipmitool' package(s) announced via the SUSE-SU-2020:0617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ipmitool fixes the following issues:
CVE-2020-5208: Fixed multiple remote code executtion vulnerabilities
 (bsc#1163026).

picmg discover messages are now DEBUG and not INFO messages
 (bsc#1085469).");

  script_tag(name:"affected", value:"'ipmitool' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipmitool", rpm:"ipmitool~1.8.18~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipmitool-debuginfo", rpm:"ipmitool-debuginfo~1.8.18~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipmitool-debugsource", rpm:"ipmitool-debugsource~1.8.18~4.3.1", rls:"SLES15.0"))) {
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
