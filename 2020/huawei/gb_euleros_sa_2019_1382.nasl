# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1382");
  script_cve_id("CVE-2018-10906");
  script_tag(name:"creation_date", value:"2020-01-23 11:41:06 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-02 17:43:45 +0000 (Tue, 02 Oct 2018)");

  script_name("Huawei EulerOS: Security Advisory for fuse (EulerOS-SA-2019-1382)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1382");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1382");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'fuse' package(s) announced via the EulerOS-SA-2019-1382 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in fuse. When SELinux is active, fusermount 1is vulnerable to a restriction bypass. This allows non-root users to mount a FUSE file system with the 'allow_other' mount option regardless of whether 'user_allow_other' is set in the fuse configuration. An attacker may use this flaw to mount a FUSE file system, accessible by other users, and trick them into accessing files on that file system, possibly causing Denial of Service or other unspecified effects.(CVE-2018-10906)");

  script_tag(name:"affected", value:"'fuse' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"fuse", rpm:"fuse~2.9.2~11.h5", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-libs", rpm:"fuse-libs~2.9.2~11.h5", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
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
