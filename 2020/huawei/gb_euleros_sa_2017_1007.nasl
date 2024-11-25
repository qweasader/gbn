# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1007");
  script_cve_id("CVE-2016-9445", "CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813");
  script_tag(name:"creation_date", value:"2020-01-23 10:42:54 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-17 19:13:15 +0000 (Tue, 17 Jan 2017)");

  script_name("Huawei EulerOS: Security Advisory for gstreamer1-plugins-bad-free (EulerOS-SA-2017-1007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1007");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1007");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gstreamer1-plugins-bad-free' package(s) announced via the EulerOS-SA-2017-1007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw, leading to a heap-based buffer overflow, was found in GStreamer's VMware VMnc video file format decoding plug-in. A remote attacker could use this flaw to cause an application using GStreamer to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2016-9445)

Multiple flaws were discovered in GStreamer's H.264 and MPEG-TS plug-ins. A remote attacker could use these flaws to cause an application using GStreamer to crash. (CVE-2016-9809, CVE-2016-9812, CVE-2016-9813)");

  script_tag(name:"affected", value:"'gstreamer1-plugins-bad-free' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free", rpm:"gstreamer1-plugins-bad-free~1.4.5~6", rls:"EULEROS-2.0SP2"))) {
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
