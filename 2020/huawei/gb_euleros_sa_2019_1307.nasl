# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1307");
  script_cve_id("CVE-2016-10087");
  script_tag(name:"creation_date", value:"2020-01-23 11:38:38 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-28 15:06:56 +0000 (Tue, 28 Feb 2017)");

  script_name("Huawei EulerOS: Security Advisory for libpng (EulerOS-SA-2019-1307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1307");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1307");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libpng' package(s) announced via the EulerOS-SA-2019-1307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The png_set_text_2 function in libpng 0.71 before 1.0.67, 1.2.x before 1.2.57, 1.4.x before 1.4.20, 1.5.x before 1.5.28, and 1.6.x before 1.6.27 allows context-dependent attackers to cause a NULL pointer dereference vectors involving loading a text chunk into a png structure, removing the text, and then adding another text chunk to the structure.(CVE-2016-10087)");

  script_tag(name:"affected", value:"'libpng' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.5.13~7.h2", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.5.13~7.h2", rls:"EULEROS-2.0SP3"))) {
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
