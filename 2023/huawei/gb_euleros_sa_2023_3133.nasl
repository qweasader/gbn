# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3133");
  script_cve_id("CVE-2023-27371");
  script_tag(name:"creation_date", value:"2023-11-09 04:28:52 +0000 (Thu, 09 Nov 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-16 18:50:58 +0000 (Thu, 16 Mar 2023)");

  script_name("Huawei EulerOS: Security Advisory for libmicrohttpd (EulerOS-SA-2023-3133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3133");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-3133");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libmicrohttpd' package(s) announced via the EulerOS-SA-2023-3133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU libmicrohttpd before 0.9.76 allows remote DoS (Denial of Service) due to improper parsing of a multipart/form-data boundary in the postprocessor.c MHD_create_post_processor() method. This allows an attacker to remotely send a malicious HTTP POST packet that includes one or more '\0' bytes in a multipart/form-data boundary field, which - assuming a specific heap layout - will result in an out-of-bounds read and a crash in the find_boundary() function.(CVE-2023-27371)");

  script_tag(name:"affected", value:"'libmicrohttpd' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmicrohttpd", rpm:"libmicrohttpd~0.9.59~3.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
