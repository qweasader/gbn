# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0429.1");
  script_cve_id("CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 15:47:00 +0000 (Tue, 21 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0429-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160429-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the SUSE-SU-2016:0429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for krb5 fixes the following issues:
- CVE-2015-8629: Information leak authenticated attackers with permissions
 to modify the database (bsc#963968)
- CVE-2015-8630: An authenticated attacker with permission to modify a
 principal entry may have caused kadmind to crash (bsc#963964)
- CVE-2015-8631: An authenticated attacker could have caused a memory leak
 in auditd by supplying a null principal name in request (bsc#963975)");

  script_tag(name:"affected", value:"'krb5' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client-debuginfo", rpm:"krb5-client-debuginfo~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo-32bit", rpm:"krb5-debuginfo-32bit~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-doc", rpm:"krb5-doc~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap-debuginfo", rpm:"krb5-plugin-kdb-ldap-debuginfo~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp-debuginfo", rpm:"krb5-plugin-preauth-otp-debuginfo~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit-debuginfo", rpm:"krb5-plugin-preauth-pkinit-debuginfo~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.1~25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.12.1~25.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client-debuginfo", rpm:"krb5-client-debuginfo~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo-32bit", rpm:"krb5-debuginfo-32bit~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-doc", rpm:"krb5-doc~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap-debuginfo", rpm:"krb5-plugin-kdb-ldap-debuginfo~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp-debuginfo", rpm:"krb5-plugin-preauth-otp-debuginfo~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit-debuginfo", rpm:"krb5-plugin-preauth-pkinit-debuginfo~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.1~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.12.1~25.1", rls:"SLES12.0SP1"))) {
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
