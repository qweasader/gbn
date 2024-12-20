# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887323");
  script_cve_id("CVE-2024-39936");
  script_tag(name:"creation_date", value:"2024-08-06 07:33:55 +0000 (Tue, 06 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 16:41:50 +0000 (Mon, 08 Jul 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-9bf3ff4133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-9bf3ff4133");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-9bf3ff4133");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295882");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-qtbase' package(s) announced via the FEDORA-2024-9bf3ff4133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix CVE-2024-39936.");

  script_tag(name:"affected", value:"'qt6-qtbase' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase", rpm:"qt6-qtbase~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-common", rpm:"qt6-qtbase-common~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-debuginfo", rpm:"qt6-qtbase-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-debugsource", rpm:"qt6-qtbase-debugsource~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-devel", rpm:"qt6-qtbase-devel~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-devel-debuginfo", rpm:"qt6-qtbase-devel-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-examples", rpm:"qt6-qtbase-examples~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-examples-debuginfo", rpm:"qt6-qtbase-examples-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-gui", rpm:"qt6-qtbase-gui~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-gui-debuginfo", rpm:"qt6-qtbase-gui-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-ibase", rpm:"qt6-qtbase-ibase~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-ibase-debuginfo", rpm:"qt6-qtbase-ibase-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-mysql", rpm:"qt6-qtbase-mysql~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-mysql-debuginfo", rpm:"qt6-qtbase-mysql-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-odbc", rpm:"qt6-qtbase-odbc~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-odbc-debuginfo", rpm:"qt6-qtbase-odbc-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-postgresql", rpm:"qt6-qtbase-postgresql~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-postgresql-debuginfo", rpm:"qt6-qtbase-postgresql-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-private-devel", rpm:"qt6-qtbase-private-devel~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtbase-static", rpm:"qt6-qtbase-static~6.7.2~3.fc40", rls:"FC40"))) {
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
