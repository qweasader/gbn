# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0189");
  script_cve_id("CVE-2015-1868");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0189");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0189.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15754");
  script_xref(name:"URL", value:"http://doc.powerdns.com/md/security/powerdns-advisory-2015-01/");
  script_xref(name:"URL", value:"http://blog.powerdns.com/2015/05/01/important-update-for-security-advisory-2015-01/");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/changelog/#powerdns-authoritative-server-332");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/changelog/#powerdns-recursor-363");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns, pdns-recursor' package(s) announced via the MGASA-2015-0189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated pdns and pdns-recursor packages fix security vulnerability:

A bug was discovered in the label decompression code in PowerDNS and PowerDNS
Recursor, making it possible for names to refer to themselves, thus causing a
loop during decompression. On some platforms, this bug can be abused to cause
crashes. On all platforms, this bug can be abused to cause service-affecting
CPU spikes (CVE-2015-1868).

The pdns package has been updated to version 3.3.2 and the pdns-recursor
package has been updated to version 3.6.3 to fix this issue and other bugs.");

  script_tag(name:"affected", value:"'pdns, pdns-recursor' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geo", rpm:"pdns-backend-geo~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~3.3.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~3.6.3~1.mga4", rls:"MAGEIA4"))) {
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
