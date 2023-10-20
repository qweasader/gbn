# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0550.1");
  script_cve_id("CVE-2013-7423", "CVE-2014-0475", "CVE-2014-7817", "CVE-2014-9402", "CVE-2015-1472");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0550-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0550-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150550-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2015:0550-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"glibc has been updated to fix four security issues:

 * CVE-2014-0475: Directory traversal in locale environment handling
 (bnc#887022)
 * CVE-2014-7817: wordexp failed to honour WRDE_NOCMD (bsc#906371)
 * CVE-2014-9402: Avoid infinite loop in nss_dns getnetbyname
 (bsc#910599)
 * CVE-2015-1472: Fixed buffer overflow in wscanf (bsc#916222)

This non-security issue has been fixed:

 * Fix missing zero termination (bnc#918233)

Security Issues:

 * CVE-2015-1472
 * CVE-2013-7423
 * CVE-2014-7817
 * CVE-2014-9402");

  script_tag(name:"affected", value:"'glibc' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.4~31.117.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.4~31.117.1", rls:"SLES10.0SP4"))) {
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
