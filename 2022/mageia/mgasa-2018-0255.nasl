# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0255");
  script_cve_id("CVE-2018-1046");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 15:58:00 +0000 (Mon, 31 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0255)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0255");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0255.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23009");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/05/09/2");
  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2018-02.html");
  script_xref(name:"URL", value:"https://blog.powerdns.com/2018/05/08/authoritative-server-4-1-2-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns' package(s) announced via the MGASA-2018-0255 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow in the dnsreplay tool occurring when
replaying a specially crafted PCAP file with the `--ecs-stamp` option
enabled, leading to a denial of service or potentially arbitrary code
execution (CVE-2018-1046).");

  script_tag(name:"affected", value:"'pdns' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~4.1.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geoip", rpm:"pdns-backend-geoip~4.1.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~4.1.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~4.1.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~4.1.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~4.1.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~4.1.2~1.mga6", rls:"MAGEIA6"))) {
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
