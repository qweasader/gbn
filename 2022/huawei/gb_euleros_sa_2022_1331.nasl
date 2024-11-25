# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1331");
  script_cve_id("CVE-2014-9462", "CVE-2016-3105", "CVE-2016-3630", "CVE-2018-13348");
  script_tag(name:"creation_date", value:"2022-03-21 06:41:12 +0000 (Mon, 21 Mar 2022)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-15 16:21:35 +0000 (Fri, 15 Apr 2016)");

  script_name("Huawei EulerOS: Security Advisory for mercurial (EulerOS-SA-2022-1331)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1331");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1331");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mercurial' package(s) announced via the EulerOS-SA-2022-1331 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The convert extension in Mercurial before 3.8 might allow context-dependent attackers to execute arbitrary code via a crafted git repository name.(CVE-2016-3105)

The binary delta decoder in Mercurial before 3.7.3 allows remote attackers to execute arbitrary code via a (1) clone, (2) push, or (3) pull command, related to (a) a list sizing rounding error and (b) short records.(CVE-2016-3630)

The _validaterepo function in sshpeer in Mercurial before 3.2.4 allows remote attackers to execute arbitrary commands via a crafted repository name in a clone command.(CVE-2014-9462)

The mpatch_decode function in mpatch.c in Mercurial before 4.6.1 mishandles certain situations where there should be at least 12 bytes remaining after the current position in the patch data, but actually are not, aka OVE-20180430-0001.(CVE-2018-13348)");

  script_tag(name:"affected", value:"'mercurial' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"mercurial", rpm:"mercurial~2.6.2~8.h4.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
