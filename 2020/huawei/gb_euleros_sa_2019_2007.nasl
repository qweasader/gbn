# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2007");
  script_cve_id("CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2019-2602", "CVE-2019-2684", "CVE-2019-2698");
  script_tag(name:"creation_date", value:"2020-01-23 12:30:38 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-25 18:12:29 +0000 (Thu, 25 Apr 2019)");

  script_name("Huawei EulerOS: Security Advisory for java-1.7.0-openjdk (EulerOS-SA-2019-2007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2007");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2007");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'java-1.7.0-openjdk' package(s) announced via the EulerOS-SA-2019-2007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenJDK: Slow conversion of BigDecimal to long (CVE-2019-2602)

OpenJDK: Incomplete enforcement of the trustURLCodebase restriction (CVE-2018-3149)

OpenJDK: Leak of sensitive header data via HTTP redirect (CVE-2018-3139)

OpenJDK: Improper field access checks (CVE-2018-3169)

OpenJDK: Font layout engine out of bounds access setCurrGlyphID() (CVE-2019-2698)

OpenJDK: Incorrect skeleton selection in RMI registry server-side dispatch handling (CVE-2019-2684)");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.191~2.6.15.4.h5", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.191~2.6.15.4.h5", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.191~2.6.15.4.h5", rls:"EULEROS-2.0SP3"))) {
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
