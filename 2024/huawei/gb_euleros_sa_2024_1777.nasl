# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1777");
  script_cve_id("CVE-2023-7104");
  script_tag(name:"creation_date", value:"2024-05-30 15:11:32 +0000 (Thu, 30 May 2024)");
  script_version("2024-05-31T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-05-31 05:05:30 +0000 (Fri, 31 May 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 17:46:29 +0000 (Mon, 08 Jan 2024)");

  script_name("Huawei EulerOS: Security Advisory for sqlite (EulerOS-SA-2024-1777)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1777");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1777");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'sqlite' package(s) announced via the EulerOS-SA-2024-1777 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in SQLite SQLite3 up to 3.43.0 and classified as critical. This issue affects the function sessionReadRecord of the file ext/session/sqlite3session.c of the component make alltest Handler. The manipulation leads to heap-based buffer overflow. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-248999.(CVE-2023-7104)");

  script_tag(name:"affected", value:"'sqlite' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"sqlite", rpm:"sqlite~3.37.2~5.h5.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
