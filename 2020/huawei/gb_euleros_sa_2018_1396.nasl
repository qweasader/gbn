# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1396");
  script_cve_id("CVE-2014-10071", "CVE-2014-10072", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-1071", "CVE-2018-1100", "CVE-2018-7549");
  script_tag(name:"creation_date", value:"2020-01-23 11:24:29 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 07:15:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Huawei EulerOS: Security Advisory for zsh (EulerOS-SA-2018-1396)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1396");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1396");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'zsh' package(s) announced via the EulerOS-SA-2018-1396 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zsh: buffer overflow for very long fds in >& fd syntax (CVE-2014-10071)

zsh: buffer overflow when scanning very long directory paths for symbolic links (CVE-2014-10072)

zsh: NULL dereference in cd in sh compatibility mode under given circumstances (CVE-2017-18205)

zsh: buffer overrun in symlinks (CVE-2017-18206)

zsh: Stack-based buffer overflow in exec.c:hashcmd() (CVE-2018-1071)

zsh: buffer overflow in utils.c:checkmailpath() can lead to local arbitrary code execution (CVE-2018-1100)

zsh: crash on copying empty hash table (CVE-2018-7549)");

  script_tag(name:"affected", value:"'zsh' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"zsh", rpm:"zsh~5.0.2~31.h1", rls:"EULEROS-2.0SP3"))) {
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
