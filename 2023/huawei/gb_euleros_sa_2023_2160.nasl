# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2160");
  script_cve_id("CVE-2022-48279", "CVE-2023-24021");
  script_tag(name:"creation_date", value:"2023-06-09 04:14:54 +0000 (Fri, 09 Jun 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:14:35 +0000 (Mon, 06 Mar 2023)");

  script_name("Huawei EulerOS: Security Advisory for mod_security (EulerOS-SA-2023-2160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2160");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-2160");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mod_security' package(s) announced via the EulerOS-SA-2023-2160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ModSecurity before 2.9.6 and 3.x before 3.0.8, HTTP multipart requests were incorrectly parsed and could bypass the Web Application Firewall. NOTE: this is related to CVE-2022-39956 but can be considered independent changes to the ModSecurity (C language) codebase.(CVE-2022-48279)

Incorrect handling of '\0' bytes in file uploads in ModSecurity before 2.9.7 may allow for Web Application Firewall bypasses and buffer over-reads on the Web Application Firewall when executing rules that read the FILES_TMP_CONTENT collection.(CVE-2023-24021)");

  script_tag(name:"affected", value:"'mod_security' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"mod_security", rpm:"mod_security~2.9.2~1.h2.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
