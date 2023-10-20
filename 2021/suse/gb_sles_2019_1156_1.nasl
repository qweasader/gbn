# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1156.1");
  script_cve_id("CVE-2016-10745", "CVE-2019-10906", "CVE-2019-8341");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:28:00 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1156-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1156-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191156-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Jinja2' package(s) announced via the SUSE-SU-2019:1156-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Jinja2 to version 2.10.1 fixes the following issues:

Security issues fixed:
CVE-2019-8341: Fixed a command injection in from_string() (bsc#1125815).

CVE-2019-10906: Fixed a sandbox escape due to information disclosure via
 str.format (bsc#1132323).");

  script_tag(name:"affected", value:"'python-Jinja2' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"python2-Jinja2", rpm:"python2-Jinja2~2.10.1~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Jinja2", rpm:"python3-Jinja2~2.10.1~3.5.1", rls:"SLES15.0"))) {
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
