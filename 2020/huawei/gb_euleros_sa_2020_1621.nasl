# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1621");
  script_cve_id("CVE-2014-2285");
  script_tag(name:"creation_date", value:"2020-06-16 05:47:03 +0000 (Tue, 16 Jun 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Huawei EulerOS: Security Advisory for net-snmp (EulerOS-SA-2020-1621)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1621");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1621");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'net-snmp' package(s) announced via the EulerOS-SA-2020-1621 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The perl_trapd_handler function in perl/TrapReceiver/TrapReceiver.xs in Net-SNMP 5.7.3.pre3 and earlier, when using certain Perl versions, allows remote attackers to cause a denial of service (snmptrapd crash) via an empty community string in an SNMP trap, which triggers a NULL pointer dereference within the newSVpv function in Perl.(CVE-2014-2285)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2~24.1.h3", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-agent-libs", rpm:"net-snmp-agent-libs~5.7.2~24.1.h3", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.7.2~24.1.h3", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.7.2~24.1.h3", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.7.2~24.1.h3", rls:"EULEROS-2.0SP2"))) {
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
