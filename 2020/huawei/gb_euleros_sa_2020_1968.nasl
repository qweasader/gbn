# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1968");
  script_cve_id("CVE-2020-11868", "CVE-2020-13817");
  script_tag(name:"creation_date", value:"2020-09-08 08:07:47 +0000 (Tue, 08 Sep 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-09 17:30:18 +0000 (Tue, 09 Jun 2020)");

  script_name("Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2020-1968)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1968");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1968");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2020-1968 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Network Time Protocol (NTP), where a security issue exists that allows an off-path attacker to prevent the Network Time Protocol daemon (ntpd) from synchronizing with NTP servers not using authentication. A server mode packet with a spoofed source address sent to the client ntpd causes the next transmission to be rescheduled, even if the packet does not have a valid origin timestamp. If the packet is sent to the client frequently enough, it stops polling the server and is unable to synchronize with it.(CVE-2020-11868)

A high-performance ntpd instance that gets its time from unauthenticated IPv4 time sources may be vulnerable to an off-path attacker who can query time from the victim's ntpd instance. An attacker who can send a large number of packets with the spoofed IPv4 address of the upstream server can use this flaw to modify the victim's clock by a limited amount or cause ntpd to exit.(CVE-2020-13817)");

  script_tag(name:"affected", value:"'ntp' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~28.h17", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~28.h17", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.6p5~28.h17", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
