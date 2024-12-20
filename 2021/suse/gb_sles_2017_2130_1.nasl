# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2130.1");
  script_cve_id("CVE-2017-2885");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-13 14:55:11 +0000 (Wed, 13 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2130-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2130-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172130-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup' package(s) announced via the SUSE-SU-2017:2130-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup fixes the following issues:
- A bug in the HTTP Chunked Encoding code has been fixed that could have
 been exploited by attackers to cause a stack-based buffer overflow in
 client or server code running libsoup (bsc#1052916, CVE-2017-2885).");

  script_tag(name:"affected", value:"'libsoup' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE OpenStack Cloud 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1", rpm:"libsoup-2_4-1~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-32bit", rpm:"libsoup-2_4-1-32bit~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-debuginfo", rpm:"libsoup-2_4-1-debuginfo~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-debuginfo-32bit", rpm:"libsoup-2_4-1-debuginfo-32bit~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-debugsource", rpm:"libsoup-debugsource~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-2_4", rpm:"typelib-1_0-Soup-2_4~2.44.2~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1", rpm:"libsoup-2_4-1~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-32bit", rpm:"libsoup-2_4-1-32bit~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-debuginfo", rpm:"libsoup-2_4-1-debuginfo~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-debuginfo-32bit", rpm:"libsoup-2_4-1-debuginfo-32bit~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-debugsource", rpm:"libsoup-debugsource~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-2_4", rpm:"typelib-1_0-Soup-2_4~2.44.2~2.3.1", rls:"SLES12.0SP1"))) {
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
