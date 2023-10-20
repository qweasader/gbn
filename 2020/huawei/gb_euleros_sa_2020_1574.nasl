# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1574");
  script_cve_id("CVE-2014-1912", "CVE-2019-14553", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575");
  script_tag(name:"creation_date", value:"2020-04-30 12:14:10 +0000 (Thu, 30 Apr 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-29 22:15:00 +0000 (Thu, 29 Apr 2021)");

  script_name("Huawei EulerOS: Security Advisory for edk2 (EulerOS-SA-2020-1574)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1574");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1574");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'edk2' package(s) announced via the EulerOS-SA-2020-1574 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the socket.recvfrom_into function in Modules/socketmodule.c in Python 2.5 before 2.7.7, 3.x before 3.3.4, and 3.4.x before 3.4rc1 allows remote attackers to execute arbitrary code via a crafted string.(CVE-2014-1912)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2019-14575)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2019-14559)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2019-14563)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2019-14553)");

  script_tag(name:"affected", value:"'edk2' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"edk2-aarch64", rpm:"edk2-aarch64~2.8.0~4", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
