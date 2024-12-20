# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1864");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868");
  script_tag(name:"creation_date", value:"2024-07-01 04:14:03 +0000 (Mon, 01 Jul 2024)");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for bind (EulerOS-SA-2024-1864)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1864");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1864");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bind' package(s) announced via the EulerOS-SA-2024-1864 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the 'KeyTrap' issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG records.(CVE-2023-50387)

The DNS message parsing code in `named` includes a section whose computational complexity is overly high. It does not cause problems for typical DNS traffic, but crafted queries and responses may cause excessive CPU load on the affected `named` instance by exploiting this flaw. This issue affects both authoritative servers and recursive resolvers.(CVE-2023-4408)

The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped) allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC responses in a random subdomain attack, aka the 'NSEC3' issue. The RFC 5155 specification implies that an algorithm must perform thousands of iterations of a hash function in certain situations.(CVE-2023-50868)");

  script_tag(name:"affected", value:"'bind' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-doc", rpm:"bind-dnssec-doc~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11", rpm:"bind-pkcs11~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-libs", rpm:"bind-pkcs11-libs~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-utils", rpm:"bind-pkcs11-utils~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.23~15.h10.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
