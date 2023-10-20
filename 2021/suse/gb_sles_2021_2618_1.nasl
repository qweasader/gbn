# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2618.1");
  script_cve_id("CVE-2020-7774", "CVE-2021-23362", "CVE-2021-27290");
  script_tag(name:"creation_date", value:"2021-08-06 14:24:45 +0000 (Fri, 06 Aug 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-19 15:41:00 +0000 (Tue, 19 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2618-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212618-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs8' package(s) announced via the SUSE-SU-2021:2618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs8 fixes the following issues:

update to npm 6.14.13

CVE-2021-27290: Fixed ssri Regular Expression Denial of Service.
 (bsc#1187976)

CVE-2021-23362: Fixed hosted-git-info Regular Expression Denial of
 Service. (bsc#1187977)

CVE-2020-7774: fixes y18n Prototype Pollution. (bsc#1184450)");

  script_tag(name:"affected", value:"'nodejs8' package(s) on SUSE Linux Enterprise Module for Web Scripting 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs8", rpm:"nodejs8~8.17.0~10.12.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debuginfo", rpm:"nodejs8-debuginfo~8.17.0~10.12.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debugsource", rpm:"nodejs8-debugsource~8.17.0~10.12.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-devel", rpm:"nodejs8-devel~8.17.0~10.12.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-docs", rpm:"nodejs8-docs~8.17.0~10.12.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm8", rpm:"npm8~8.17.0~10.12.2", rls:"SLES15.0SP2"))) {
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
