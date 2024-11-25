# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1459.1");
  script_cve_id("CVE-2021-44906", "CVE-2021-44907", "CVE-2022-0235", "CVE-2022-0778");
  script_tag(name:"creation_date", value:"2022-04-29 04:27:10 +0000 (Fri, 29 Apr 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-23 18:57:27 +0000 (Wed, 23 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1459-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221459-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs14' package(s) announced via the SUSE-SU-2022:1459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs14 fixes the following issues:

CVE-2022-0778: Fixed a infinite loop in BN_mod_sqrt() reachable when
 parsing certificates (bsc#1196877).

CVE-2021-44906: Fixed a prototype pollution in node-minimist
 (bsc#1198247).

CVE-2021-44907: Fixed a potential Denial of Service vulnerability in
 node-qs (bsc#1197283).

CVE-2022-0235: Fixed an exposure of sensitive information to an
 unauthorized actor in node-fetch (bsc#1194819).");

  script_tag(name:"affected", value:"'nodejs14' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs14", rpm:"nodejs14~14.19.1~6.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debuginfo", rpm:"nodejs14-debuginfo~14.19.1~6.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debugsource", rpm:"nodejs14-debugsource~14.19.1~6.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-devel", rpm:"nodejs14-devel~14.19.1~6.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-docs", rpm:"nodejs14-docs~14.19.1~6.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm14", rpm:"npm14~14.19.1~6.28.1", rls:"SLES12.0"))) {
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
