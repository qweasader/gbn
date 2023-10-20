# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1208");
  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10243");
  script_tag(name:"creation_date", value:"2020-01-23 10:59:08 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 18:05:00 +0000 (Fri, 12 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for java-1.7.0-openjdk (EulerOS-SA-2017-1208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1208");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1208");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'java-1.7.0-openjdk' package(s) announced via the EulerOS-SA-2017-1208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the DCG implementation in the RMI component of OpenJDK failed to correctly handle references. A remote attacker could possibly use this flaw to execute arbitrary code with the privileges of RMI registry or a Java RMI application. (CVE-2017-10102)

Multiple flaws were discovered in the RMI, JAXP, ImageIO, Libraries, AWT, Hotspot, and Security components in OpenJDK. An untrusted Java application or applet could use these flaws to completely bypass Java sandbox restrictions. (CVE-2017-10107, CVE-2017-10096, CVE-2017-10101, CVE-2017-10089, CVE-2017-10090, CVE-2017-10087, CVE-2017-10110, CVE-2017-10074, CVE-2017-10067)

It was discovered that the LDAPCertStore class in the Security component of OpenJDK followed LDAP referrals to arbitrary URLs. A specially crafted LDAP referral URL could cause LDAPCertStore to communicate with non-LDAP servers. (CVE-2017-10116)

It was discovered that the wsdlimport tool in the JAX-WS component of OpenJDK did not use secure XML parser settings when parsing WSDL XML documents. A specially crafted WSDL document could cause wsdlimport to use an excessive amount of CPU and memory, open connections to other hosts, or leak information. (CVE-2017-10243)

A covert timing channel flaw was found in the DSA implementation in the JCE component of OpenJDK. A remote attacker able to make a Java application generate DSA signatures on demand could possibly use this flaw to extract certain information about the used key via a timing side channel. (CVE-2017-10115)

A covert timing channel flaw was found in the PKCS#8 implementation in the JCE component of OpenJDK. A remote attacker able to make a Java application repeatedly compare PKCS#8 key against an attacker controlled value could possibly use this flaw to determine the key via a timing side channel. (CVE-2017-10135)

It was discovered that the BasicAttribute and CodeSource classes in OpenJDK did not limit the amount of memory allocated when creating object instances from a serialized form. A specially crafted serialized input stream could cause Java to consume an excessive amount of memory. (CVE-2017-10108, CVE-2017-10109)

A flaw was found in the Hotspot component in OpenJDK. An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions. (CVE-2017-10081)

It was discovered that the JPEGImageReader implementation in the 2D component of OpenJDK would, in certain cases, read all image data even if it was not used later. A specially crafted image could cause a Java application to temporarily use an excessive amount of CPU and memory. (CVE-2017-10053)");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.151~2.6.11.1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.151~2.6.11.1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.151~2.6.11.1", rls:"EULEROS-2.0SP2"))) {
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
