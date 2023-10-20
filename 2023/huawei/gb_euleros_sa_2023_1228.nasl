# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1228");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for net-snmp (EulerOS-SA-2023-1228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1228");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1228");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'net-snmp' package(s) announced via the EulerOS-SA-2023-1228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in net-snmp. A buffer overflow in the handling of the INDEX of NET-SNMP-VACM-MIB can cause an out-of-bounds memory access issue.(CVE-2022-24805)

A flaw was found in net-snmp. A malformed OID in a SET to the nsVacmAccessTable can cause a NULL pointer dereference issue.(CVE-2022-24810)

A flaw was found in net-snmp. A malformed OID in a GET-NEXT to the nsVacmAccessTable can cause a NULL pointer dereference issue.(CVE-2022-24809)

A flaw was found in net-snmp. A malformed OID in a SET request to NET-SNMP-AGENT-MIB::nsLogTable can cause a NULL pointer dereference issue.(CVE-2022-24808)

A flaw was found in net-snmp. A malformed OID in a SET request to the SNMP-VIEW-BASED-ACM-MIB::vacmAccessTable can cause an out-of-bounds memory access issue.(CVE-2022-24807)

A flaw was found in net-snmp. This issue occurs due to improper input validation when simultaneously setting malformed OIDs in the master agent and subagent.(CVE-2022-24806)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.8~8.h7.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.8~8.h7.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-net-snmp", rpm:"python3-net-snmp~5.8~8.h7.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
