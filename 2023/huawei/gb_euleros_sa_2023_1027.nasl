# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1027");
  script_cve_id("CVE-2022-2795", "CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-23 16:44:59 +0000 (Fri, 23 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for bind (EulerOS-SA-2023-1027)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1027");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-1027");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bind' package(s) announced via the EulerOS-SA-2023-1027 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Bind package. By spoofing the target resolver with responses that have a malformed ECDSA signature, an attacker can trigger a small memory leak, resulting in crashing the program.(CVE-2022-38177)

By flooding the target resolver with queries exploiting this flaw an attacker can significantly impair the resolver's performance, effectively denying legitimate clients access to the DNS resolution service.(CVE-2022-2795)

A flaw was found in the Bind package, where the DNSSEC verification code for the EdDSA algorithm leaks memory when there is a signature length mismatch. By spoofing the target resolver with responses that have a malformed EdDSA signature, an attacker can trigger a small memory leak, resulting in crashing the program.(CVE-2022-38178)

A flaw was found in the Bind package, where the resolver can crash when stale cache and stale answers are enabled, option stale-answer-client-timeout is set to 0 and there is a stale CNAME in the cache for an incoming query. By sending specific queries to the resolver, an attacker can cause named to crash.(CVE-2022-3080)");

  script_tag(name:"affected", value:"'bind' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-doc", rpm:"bind-dnssec-doc~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11", rpm:"bind-pkcs11~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-libs", rpm:"bind-pkcs11-libs~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-utils", rpm:"bind-pkcs11-utils~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.23~6.h8.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
