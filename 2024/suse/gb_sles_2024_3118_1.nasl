# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3118.1");
  script_cve_id("CVE-2024-23184", "CVE-2024-23185");
  script_tag(name:"creation_date", value:"2024-09-04 04:26:54 +0000 (Wed, 04 Sep 2024)");
  script_version("2024-09-04T05:16:32+0000");
  script_tag(name:"last_modification", value:"2024-09-04 05:16:32 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3118-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3118-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243118-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot23' package(s) announced via the SUSE-SU-2024:3118-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot23 fixes the following issues:

CVE-2024-23185: Fixed a denial of service with large headers (bsc#1229183)
CVE-2024-23184: Fixed a denial of service parsing messages containing many address headers (bsc#1229184)");

  script_tag(name:"affected", value:"'dovecot23' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.15~150200.65.1", rls:"SLES15.0SP4"))) {
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
