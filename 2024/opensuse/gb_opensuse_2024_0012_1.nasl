# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833202");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-51764");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 16:19:53 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:49 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for postfix (SUSE-SU-2024:0012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0012-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G26ZRDRO3D4M2LVHPFAY45WE6ZBCPVW6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix'
  package(s) announced via the SUSE-SU-2024:0012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postfix fixes the following issues:

  * CVE-2023-51764: Fixed SMTP smuggling attack (bsc#1218304).

  ##");

  script_tag(name:"affected", value:"'postfix' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.5.9~150300.5.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.5.9~150300.5.15.1", rls:"openSUSELeap15.3"))) {
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