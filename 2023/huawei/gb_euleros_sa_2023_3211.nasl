# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3211");
  script_cve_id("CVE-2023-43115");
  script_tag(name:"creation_date", value:"2023-11-10 04:21:14 +0000 (Fri, 10 Nov 2023)");
  script_version("2024-02-23T05:07:12+0000");
  script_tag(name:"last_modification", value:"2024-02-23 05:07:12 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-22 17:49:00 +0000 (Thu, 22 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2023-3211)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3211");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-3211");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2023-3211 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Artifex Ghostscript through 10.01.2, gdevijs.c in GhostPDL can lead to remote code execution via crafted PostScript documents because they can switch to the IJS device, or change the IjsServer parameter, after SAFER has been activated. NOTE: it is a documented risk that the IJS server can be specified on a gs command line (the IJS device inherently must execute a command to start the IJS server).(CVE-2023-43115)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.52~4.h7.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-help", rpm:"ghostscript-help~9.52~4.h7.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
