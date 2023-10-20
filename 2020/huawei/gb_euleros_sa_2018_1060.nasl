# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1060");
  script_cve_id("CVE-2018-7050", "CVE-2018-7051", "CVE-2018-7052");
  script_tag(name:"creation_date", value:"2020-01-23 11:11:06 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-28 17:37:00 +0000 (Thu, 28 Feb 2019)");

  script_name("Huawei EulerOS: Security Advisory for irssi (EulerOS-SA-2018-1060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1060");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1060");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'irssi' package(s) announced via the EulerOS-SA-2018-1060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Irssi before 1.0.7 and 1.1.x before 1.1.1. A NULL pointer dereference occurs for an 'empty' nick.( CVE-2018-7050)

An issue was discovered in Irssi before 1.0.7 and 1.1.x before 1.1.1. Certain nick names could result in out-of-bounds access when printing theme strings.(CVE-2018-7051)

An issue was discovered in Irssi before 1.0.7 and 1.1.x before 1.1.1. When the number of windows exceeds the available space, a crash due to a NULL pointer dereference would occur.(CVE-2018-7052)");

  script_tag(name:"affected", value:"'irssi' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.15~16.h5", rls:"EULEROS-2.0SP1"))) {
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
