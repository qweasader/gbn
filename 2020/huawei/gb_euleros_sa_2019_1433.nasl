# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1433");
  script_cve_id("CVE-2014-0591", "CVE-2014-8500", "CVE-2015-1349", "CVE-2015-4620", "CVE-2015-5477", "CVE-2015-5722", "CVE-2015-8000", "CVE-2016-1285", "CVE-2016-1286", "CVE-2016-2775", "CVE-2016-2776", "CVE-2016-8864", "CVE-2016-9131", "CVE-2017-3136", "CVE-2017-3142", "CVE-2017-3143", "CVE-2017-3145", "CVE-2018-5740");
  script_tag(name:"creation_date", value:"2020-01-23 11:45:55 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-28 14:49:08 +0000 (Wed, 28 Sep 2016)");

  script_name("Huawei EulerOS: Security Advisory for bind (EulerOS-SA-2019-1433)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1433");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1433");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bind' package(s) announced via the EulerOS-SA-2019-1433 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the way BIND constructed a response to a query that met certain criteria. A remote attacker could use this flaw to make named exit unexpectedly with an assertion failure via a specially crafted DNS request packet.(CVE-2016-2776)

A denial of service flaw was found in the way BIND processed certain control channel input. A remote attacker able to send a malformed packet to the control channel could use this flaw to cause named to crash.(CVE-2016-1285)

A flaw was found in the way BIND performed DNSSEC validation. An attacker able to make BIND (functioning as a DNS resolver with DNSSEC validation enabled) resolve a name in an attacker-controlled domain could cause named to exit unexpectedly with an assertion failure.(CVE-2015-4620)

A flaw was found in the way BIND handled requests for TKEY DNS resource records. A remote attacker could use this flaw to make named (functioning as an authoritative DNS server or a DNS resolver) exit unexpectedly with an assertion failure via a specially crafted DNS request packet.(CVE-2015-5477)

A denial of service flaw was found in the way BIND handled queries for NSEC3-signed zones. A remote attacker could use this flaw against an authoritative name server that served NCES3-signed zones by sending a specially crafted query, which, when processed, would cause named to crash.(CVE-2014-0591)

A denial of service flaw was found in the way BIND parsed certain malformed DNSSEC keys. A remote attacker could use this flaw to send a specially crafted DNS query (for example, a query requiring a response from a zone containing a deliberately malformed key) that would cause named functioning as a validating resolver to crash.(CVE-2015-5722)

It was found that the lightweight resolver protocol implementation in BIND could enter an infinite recursion and crash when asked to resolve a query name which, when combined with a search list entry, exceeds the maximum allowable length. A remote attacker could use this flaw to crash lwresd or named when using the 'lwres' statement in named.conf.(CVE-2016-2775)

A denial of service flaw was found in the way BIND processed certain records with malformed class attributes. A remote attacker could use this flaw to send a query to request a cached record with a malformed class attribute that would cause named functioning as an authoritative or recursive server to crash. Note: This issue affects authoritative servers as well as recursive servers, however authoritative servers are at limited risk if they perform authentication when making recursive queries to resolve addresses for servers listed in NS RRSETs.(CVE-2015-8000)

A denial of service flaw was found in the way BIND handled responses containing a DNAME answer. A remote attacker could use this flaw to make named exit unexpectedly with an assertion failure via a specially crafted DNS response.(CVE-2016-8864)

A denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'bind' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.4~61.1.h2", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-lite", rpm:"bind-libs-lite~9.9.4~61.1.h2", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.9.4~61.1.h2", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.4~61.1.h2", rls:"EULEROSVIRT-3.0.1.0"))) {
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
