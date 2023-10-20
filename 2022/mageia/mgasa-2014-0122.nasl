# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0122");
  script_cve_id("CVE-2014-2284", "CVE-2014-2285");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0122");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0122.html");
  script_xref(name:"URL", value:"http://freecode.com/projects/net-snmp/releases/361848");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/03/05/9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1070396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1072778");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12880");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the MGASA-2014-0122 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated net-snmp packages fix security vulnerabilities:

Remotely exploitable denial of service vulnerability in Net-SNMP, in the
Linux implementation of the ICMP-MIB, making the SNMP agent vulnerable if it
is making use of the ICMP-MIB table objects (CVE-2014-2284).

Remotely exploitable denial of service vulnerability in Net-SNMP, in
snmptrapd, due to how it handles trap requests with an empty community string
when the perl handler is enabled (CVE-2014-2285).");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp-devel", rpm:"lib64net-snmp-devel~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp-static-devel", rpm:"lib64net-snmp-static-devel~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp30", rpm:"lib64net-snmp30~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp-devel", rpm:"libnet-snmp-devel~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp-static-devel", rpm:"libnet-snmp-static-devel~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp30", rpm:"libnet-snmp30~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-tkmib", rpm:"net-snmp-tkmib~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-NetSNMP", rpm:"perl-NetSNMP~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-netsnmp", rpm:"python-netsnmp~5.7.2~7.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp-devel", rpm:"lib64net-snmp-devel~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp-static-devel", rpm:"lib64net-snmp-static-devel~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp30", rpm:"lib64net-snmp30~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp-devel", rpm:"libnet-snmp-devel~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp-static-devel", rpm:"libnet-snmp-static-devel~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp30", rpm:"libnet-snmp30~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-tkmib", rpm:"net-snmp-tkmib~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-NetSNMP", rpm:"perl-NetSNMP~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-netsnmp", rpm:"python-netsnmp~5.7.2~13.1.mga4", rls:"MAGEIA4"))) {
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
