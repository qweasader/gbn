# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2367.1");
  script_cve_id("CVE-2024-3596");
  script_tag(name:"creation_date", value:"2024-07-10 04:28:31 +0000 (Wed, 10 Jul 2024)");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2367-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242367-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius-server' package(s) announced via the SUSE-SU-2024:2367-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freeradius-server fixes the following issues:

CVE-2024-3596: Fixed chosen-prefix collision attack against MD5 (bsc#1223414).");

  script_tag(name:"affected", value:"'freeradius-server' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-devel", rpm:"freeradius-server-devel~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5-debuginfo", rpm:"freeradius-server-krb5-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap-debuginfo", rpm:"freeradius-server-ldap-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql-debuginfo", rpm:"freeradius-server-mysql-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl-debuginfo", rpm:"freeradius-server-perl-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql-debuginfo", rpm:"freeradius-server-postgresql-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python3", rpm:"freeradius-server-python3~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python3-debuginfo", rpm:"freeradius-server-python3-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite-debuginfo", rpm:"freeradius-server-sqlite-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-devel", rpm:"freeradius-server-devel~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5-debuginfo", rpm:"freeradius-server-krb5-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap-debuginfo", rpm:"freeradius-server-ldap-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql-debuginfo", rpm:"freeradius-server-mysql-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl-debuginfo", rpm:"freeradius-server-perl-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql-debuginfo", rpm:"freeradius-server-postgresql-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python3", rpm:"freeradius-server-python3~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python3-debuginfo", rpm:"freeradius-server-python3-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite-debuginfo", rpm:"freeradius-server-sqlite-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~3.0.21~150200.3.15.1", rls:"SLES15.0SP3"))) {
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
