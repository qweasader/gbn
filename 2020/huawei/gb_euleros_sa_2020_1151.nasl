# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1151");
  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2019-19604");
  script_tag(name:"creation_date", value:"2020-02-25 13:57:02 +0000 (Tue, 25 Feb 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 19:20:30 +0000 (Wed, 05 Feb 2020)");

  script_name("Huawei EulerOS: Security Advisory for git (EulerOS-SA-2020-1151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1151");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1151");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2020-1151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was found in Git before v2.24.1, v2.23.1, v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3, v2.16.6, v2.15.4, and v2.14.6. The --export-marks option of git fast-import is exposed also via the in-stream command feature export-marks=... and it allows overwriting arbitrary paths.(CVE-2019-1348)

A remote code execution vulnerability exists when Git for Visual Studio improperly sanitizes input, aka 'Git for Visual Studio Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1350, CVE-2019-1352, CVE-2019-1354, CVE-2019-1387.(CVE-2019-1349)

A remote code execution vulnerability exists when Git for Visual Studio improperly sanitizes input, aka 'Git for Visual Studio Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1349, CVE-2019-1352, CVE-2019-1354, CVE-2019-1387.(CVE-2019-1350)

A tampering vulnerability exists when Git for Visual Studio improperly handles virtual drive paths, aka 'Git for Visual Studio Tampering Vulnerability'.(CVE-2019-1351)

A remote code execution vulnerability exists when Git for Visual Studio improperly sanitizes input, aka 'Git for Visual Studio Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1349, CVE-2019-1350, CVE-2019-1354, CVE-2019-1387.(CVE-2019-1352)

An issue was found in Git before v2.24.1, v2.23.1, v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3, v2.16.6, v2.15.4, and v2.14.6. When running Git in the Windows Subsystem for Linux (also known as 'WSL') while accessing a working directory on a regular Windows drive, none of the NTFS protections were active.(CVE-2019-1353)

A remote code execution vulnerability exists when Git for Visual Studio improperly sanitizes input, aka 'Git for Visual Studio Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1349, CVE-2019-1350, CVE-2019-1352, CVE-2019-1387.(CVE-2019-1354)

An issue was found in Git before v2.24.1, v2.23.1, v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3, v2.16.6, v2.15.4, and v2.14.6. Recursive clones are currently affected by a vulnerability that is caused by too-lax validation of submodule names, allowing very targeted attacks via remote code execution in recursive clones.(CVE-2019-1387)

Arbitrary command execution is possible in Git before 2.20.2, 2.21.x before 2.21.1, 2.22.x before 2.22.2, 2.23.x before 2.23.1, and 2.24.x before 2.24.1 because a 'git submodule update' operation can run commands found in the .gitmodules file of a malicious repository.(CVE-2019-19604)");

  script_tag(name:"affected", value:"'git' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.19.1~1.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.19.1~1.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-doc", rpm:"git-core-doc~2.19.1~1.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~2.19.1~1.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
