# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3005");
  script_cve_id("CVE-2023-4156");
  script_tag(name:"creation_date", value:"2023-10-31 04:19:09 +0000 (Tue, 31 Oct 2023)");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 19:39:00 +0000 (Tue, 26 Sep 2023)");

  script_name("Huawei EulerOS: Security Advisory for gawk (EulerOS-SA-2023-3005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=(EULEROS\-2\.0SP11|EULEROSVIRT\-2\.9\.0)");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3005");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3005");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gawk' package(s) announced via the EulerOS-SA-2023-3005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap out-of-bounds read flaw was found in builtin.c in the gawk package. This issue may lead to a crash and could be used to read sensitive information.(CVE-2023-4156)");

  script_tag(name:"affected", value:"'gawk' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"gawk", rpm:"gawk~5.1.1~1.h2.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.1.0~1.h1.r26.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
