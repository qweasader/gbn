# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1756");
  script_cve_id("CVE-2018-10916");
  script_tag(name:"creation_date", value:"2020-07-03 06:22:43 +0000 (Fri, 03 Jul 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-02 18:29:00 +0000 (Tue, 02 Apr 2019)");

  script_name("Huawei EulerOS: Security Advisory for lftp (EulerOS-SA-2020-1756)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1756");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1756");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'lftp' package(s) announced via the EulerOS-SA-2020-1756 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that lftp up to and including version 4.8.3 does not properly sanitize remote file names, leading to a loss of integrity on the local system when reverse mirroring is used. A remote attacker may trick a user to use reverse mirroring on an attacker controlled FTP server, resulting in the removal of all files in the current working directory of the victim's system.(CVE-2018-10916)");

  script_tag(name:"affected", value:"'lftp' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"lftp", rpm:"lftp~4.4.8~8.2.h6", rls:"EULEROSVIRT-3.0.6.0"))) {
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
