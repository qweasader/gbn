# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1222");
  script_cve_id("CVE-2015-7705", "CVE-2015-7853", "CVE-2015-7871", "CVE-2018-7185");
  script_tag(name:"creation_date", value:"2020-01-23 11:35:31 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 12:15:00 +0000 (Tue, 13 Apr 2021)");

  script_name("Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2019-1222)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.5\.3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1222");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1222");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2019-1222 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The rate limiting feature in NTP 4.x before 4.2.8p4 and 4.3.x before 4.3.77 allows remote attackers to have unspecified impact via a large number of crafted requests.(CVE-2015-7705)

The datalen parameter in the refclock driver in NTP 4.2.x before 4.2.8p4, and 4.3.x before 4.3.77 allows remote attackers to execute arbitrary code or cause a denial of service (crash) via a negative input value.(CVE-2015-7853)

Crypto-NAK packets in ntpd in NTP 4.2.x before 4.2.8p4, and 4.3.x before 4.3.77 allows remote attackers to bypass authentication.(CVE-2015-7871)

The protocol engine in ntp 4.2.6 before 4.2.8p11 allows a remote attacker to cause a denial of service (disruption) by continually sending a packet with a zero-origin timestamp and source IP address of the 'other side' of an interleaved association causing the victim ntpd to reset its association.(CVE-2018-7185)");

  script_tag(name:"affected", value:"'ntp' package(s) on Huawei EulerOS Virtualization 2.5.3.");

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

if(release == "EULEROSVIRT-2.5.3") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~25.0.1.h18", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~25.0.1.h18", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.6p5~25.0.1.h18", rls:"EULEROSVIRT-2.5.3"))) {
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
