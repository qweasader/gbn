# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2326.1");
  script_cve_id("CVE-2020-7774", "CVE-2021-22918", "CVE-2021-23362", "CVE-2021-27290", "CVE-2021-3449", "CVE-2021-3450");
  script_tag(name:"creation_date", value:"2021-07-15 09:14:13 +0000 (Thu, 15 Jul 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-03 16:07:08 +0000 (Thu, 03 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2326-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212326-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs12' package(s) announced via the SUSE-SU-2021:2326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs12 fixes the following issues:

update to 12.22.2:

CVE-2021-22918: Out of bounds read (bsc#1187973)

CVE-2021-23362: ssri Regular Expression Denial of Service and
 hosted-git-info (bsc#1187977)

CVE-2021-27290: Regular Expression Denial of Service (bsc#1187976)

CVE-2021-3450: OpenSSL - CA certificate check bypass with
 X509_V_FLAG_X509_STRICT (bsc#1183851)

CVE-2021-3449: OpenSSL - NULL pointer deref in signature_algorithms
 processing (bsc#1183852)

CVE-2020-7774: npm - Update y18n to fix Prototype-Pollution (bsc#1184450)");

  script_tag(name:"affected", value:"'nodejs12' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs12", rpm:"nodejs12~12.22.2~1.32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debuginfo", rpm:"nodejs12-debuginfo~12.22.2~1.32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debugsource", rpm:"nodejs12-debugsource~12.22.2~1.32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-devel", rpm:"nodejs12-devel~12.22.2~1.32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-docs", rpm:"nodejs12-docs~12.22.2~1.32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm12", rpm:"npm12~12.22.2~1.32.1", rls:"SLES12.0"))) {
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
