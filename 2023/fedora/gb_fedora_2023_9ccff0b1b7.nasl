# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884815");
  script_cve_id("CVE-2022-4899", "CVE-2023-21911", "CVE-2023-21919", "CVE-2023-21920", "CVE-2023-21929", "CVE-2023-21933", "CVE-2023-21935", "CVE-2023-21940", "CVE-2023-21945", "CVE-2023-21946", "CVE-2023-21947", "CVE-2023-21953", "CVE-2023-21955", "CVE-2023-21962", "CVE-2023-22005", "CVE-2023-22008", "CVE-2023-22033", "CVE-2023-22038", "CVE-2023-22046", "CVE-2023-22048", "CVE-2023-22053", "CVE-2023-22054", "CVE-2023-22056", "CVE-2023-22057", "CVE-2023-22058");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:34 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 01:19:54 +0000 (Fri, 07 Apr 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-9ccff0b1b7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9ccff0b1b7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-9ccff0b1b7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2183136");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196534");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225741");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231876");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-34.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql' package(s) announced via the FEDORA-2023-9ccff0b1b7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MySQL 8.0.34**

Release notes:

 [link moved to references]");

  script_tag(name:"affected", value:"'community-mysql' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-common", rpm:"community-mysql-common~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-debuginfo", rpm:"community-mysql-debuginfo~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-debugsource", rpm:"community-mysql-debugsource~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-devel", rpm:"community-mysql-devel~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-devel-debuginfo", rpm:"community-mysql-devel-debuginfo~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-errmsg", rpm:"community-mysql-errmsg~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-libs", rpm:"community-mysql-libs~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-libs-debuginfo", rpm:"community-mysql-libs-debuginfo~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-server", rpm:"community-mysql-server~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-server-debuginfo", rpm:"community-mysql-server-debuginfo~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-test", rpm:"community-mysql-test~8.0.34~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-test-debuginfo", rpm:"community-mysql-test-debuginfo~8.0.34~2.fc39", rls:"FC39"))) {
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
