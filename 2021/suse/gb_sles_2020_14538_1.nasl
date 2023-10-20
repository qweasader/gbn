# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14538.1");
  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:50 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-30 13:48:00 +0000 (Tue, 30 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14538-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14538-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014538-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2020:14538-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

cobbler:

Fix parsing cobbler dictionary options with values containing '=', e.g.
 kernel params containing '=' (bsc#1176978)

mgr-daemon:

Update translation strings

salt:

Properly validate eauth credentials and tokens on SSH calls made by Salt
 API (bsc#1178319, bsc#1178362, bsc#1178361, CVE-2020-25592,
 CVE-2020-17490, CVE-2020-16846)

spacecmd:

Python3 fixes for errata in spacecmd (bsc#1169664)

Added support for i18n of user-facing strings

Python3 fix for sorted usage (bsc#1167907)

spacewalk-client-tools:

Remove RH references in Python/Ruby localization and use the product
 name instead");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"koan", rpm:"koan~2.2.2~0.68.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.1.3~5.20.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon-debuginfo", rpm:"mgr-daemon-debuginfo~4.1.3~5.20.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon-debugsource", rpm:"mgr-daemon-debugsource~4.1.3~5.20.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.1.7~27.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.1.7~27.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.1.7~27.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~43.63.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~43.63.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~43.63.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.1.8~18.72.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.1.7~27.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.1.7~27.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.1.7~27.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"koan", rpm:"koan~2.2.2~0.68.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.1.3~5.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon-debuginfo", rpm:"mgr-daemon-debuginfo~4.1.3~5.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon-debugsource", rpm:"mgr-daemon-debugsource~4.1.3~5.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.1.7~27.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.1.7~27.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.1.7~27.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~43.63.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~43.63.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~43.63.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.1.8~18.72.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.1.7~27.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.1.7~27.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.1.7~27.38.1", rls:"SLES11.0SP4"))) {
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
