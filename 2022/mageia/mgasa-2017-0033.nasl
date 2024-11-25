# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0033");
  script_cve_id("CVE-2016-2120", "CVE-2016-7068", "CVE-2016-7072", "CVE-2016-7073", "CVE-2016-7074");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-07 19:56:38 +0000 (Mon, 07 Jan 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0033");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0033.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20126");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-02/");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-03/");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-04/");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-05/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3764");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns' package(s) announced via the MGASA-2017-0033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathieu Lafon discovered that pdns does not properly validate records
in zones. An authorized user can take advantage of this flaw to crash
server by inserting a specially crafted record in a zone under their
control and then sending a DNS query for that record (CVE-2016-2120).

Florian Heinz and Martin Kluge reported that pdns parses all records
present in a query regardless of whether they are needed or even
legitimate, allowing a remote, unauthenticated attacker to cause an
abnormal CPU usage load on the pdns server, resulting in a partial
denial of service if the system becomes overloaded (CVE-2016-7068).

Mongo discovered that the webserver in pdns is susceptible to a
denial-of-service vulnerability. A remote, unauthenticated attacker to
cause a denial of service by opening a large number of f TCP
connections to the web server (CVE-2016-7072).

Mongo discovered that pdns does not sufficiently validate TSIG
signatures, allowing an attacker in position of man-in-the-middle to
alter the content of an AXFR (CVE-2016-7073, CVE-2016-7074).");

  script_tag(name:"affected", value:"'pdns' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geo", rpm:"pdns-backend-geo~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~3.3.3~1.3.mga5", rls:"MAGEIA5"))) {
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
