# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2464");
  script_cve_id("CVE-2021-2341", "CVE-2021-2369", "CVE-2021-2388");
  script_tag(name:"creation_date", value:"2021-09-24 02:24:28 +0000 (Fri, 24 Sep 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-26 17:05:18 +0000 (Mon, 26 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for java-1.8.0-openjdk (EulerOS-SA-2021-2464)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2464");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-2464");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'java-1.8.0-openjdk' package(s) announced via the EulerOS-SA-2021-2464 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1, Oracle GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator).(CVE-2021-2369)

Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1, Oracle GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator).(CVE-2021-2341)

Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Hotspot). Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1, Oracle GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.181.b15~5.h23.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.181.b15~5.h23.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.181.b15~5.h23.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
