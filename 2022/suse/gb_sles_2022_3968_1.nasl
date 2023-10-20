# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3968.1");
  script_cve_id("CVE-2022-43548");
  script_tag(name:"creation_date", value:"2022-11-15 04:21:58 +0000 (Tue, 15 Nov 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 16:02:00 +0000 (Thu, 08 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3968-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3968-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223968-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs14' package(s) announced via the SUSE-SU-2022:3968-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs14 fixes the following issues:

Update to 14.21.1:

CVE-2022-43548: Fixed DNS rebinding in --inspect via invalid octal IP
 address (bsc#1205119).

Update to 14.21.0:

src: add --openssl-shared-config option");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs14", rpm:"nodejs14~14.21.1~6.37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debuginfo", rpm:"nodejs14-debuginfo~14.21.1~6.37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debugsource", rpm:"nodejs14-debugsource~14.21.1~6.37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-devel", rpm:"nodejs14-devel~14.21.1~6.37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-docs", rpm:"nodejs14-docs~14.21.1~6.37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm14", rpm:"npm14~14.21.1~6.37.1", rls:"SLES12.0"))) {
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
