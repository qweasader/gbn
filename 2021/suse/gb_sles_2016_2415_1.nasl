# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2415.1");
  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-14 17:59:40 +0000 (Wed, 14 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2415-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2415-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162415-1/");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.4/static/release-9-4-9.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.4/static/release-9-4-8.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.4/static/release-9-4-7.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2016:2415-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql94 to version 9.4.9 fixes the several issues.
These security issues were fixed:
- CVE-2016-5423: CASE/WHEN with inlining can cause untrusted pointer
 dereference (bsc#993454).
- CVE-2016-5424: Fix client programs' handling of special characters in
 database and role names (bsc#993453).
This non-security issue was fixed:
- bsc#973660: Added 'Requires: timezone' to Service Pack For additional non-security issues please refer to
- [link moved to references]
- [link moved to references]
- [link moved to references]");

  script_tag(name:"affected", value:"'postgresql94' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo-32bit", rpm:"libpq5-debuginfo-32bit~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib-debuginfo", rpm:"postgresql94-contrib-debuginfo~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debuginfo", rpm:"postgresql94-debuginfo~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debugsource", rpm:"postgresql94-debugsource~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-libs-debugsource", rpm:"postgresql94-libs-debugsource~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.9~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server-debuginfo", rpm:"postgresql94-server-debuginfo~9.4.9~14.1", rls:"SLES12.0SP1"))) {
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
