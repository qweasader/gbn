# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1060");
  script_cve_id("CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5196", "CVE-2015-5219", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7852", "CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8158");
  script_tag(name:"creation_date", value:"2020-01-23 10:41:31 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-07 14:58:04 +0000 (Tue, 07 Feb 2017)");

  script_name("Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2016-1060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2016-1060");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2016-1060");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2016-1060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that ntpd could crash due to an uninitialized variable when processing malformed logconfig configuration commands.(CVE-2015-5194)

It was found that ntpd would exit with a segmentation fault when a statistics type that was not enabled during compilation (e.g. timingstats) was referenced by the statistics or filegen configuration command.(CVE-2015-5195)

It was found that NTP's :config command could be used to set the pidfile and driftfile paths without any restrictions. A remote attacker could use this flaw to overwrite a file on the file system with a file containing the pid of the ntpd process (immediately) or the current estimated drift of the system clock (in hourly intervals).(CVE-2015-5196)

It was discovered that the sntp utility could become unresponsive due to being caught in an infinite loop when processing a crafted NTP packet.(CVE-2015-5219)

It was found that the fix for CVE-2014-9750 was incomplete: three issues were found in the value length checks in NTP's ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. A remote attacker could use a specially crafted NTP packet to crash ntpd.(CVE-2015-7691)

It was found that the fix for CVE-2014-9750 was incomplete: three issues were found in the value length checks in NTP's ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. A remote attacker could use a specially crafted NTP packet to crash ntpd.(CVE-2015-7692)

A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd was configured to use autokey authentication, an attacker could send packets to ntpd that would, after several days of ongoing attack, cause it to run out of memory.(CVE-2015-7701)

It was found that the fix for CVE-2014-9750 was incomplete: three issues were found in the value length checks in NTP's ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. A remote attacker could use a specially crafted NTP packet to crash ntpd.(CVE-2015-7702)

It was found that NTP's :config command could be used to set the pidfile and driftfile paths without any restrictions. A remote attacker could use this flaw to overwrite a file on the file system with a file containing the pid of the ntpd process (immediately) or the current estimated drift of the system clock (in hourly intervals).(CVE-2015-7703)

An off-by-one flaw, leading to a buffer overflow, was found in cookedprint functionality of ntpq. A specially crafted NTP packet could potentially cause ntpq to crash.(CVE-2015-7852)

A flaw was found in the way NTP verified trusted keys during symmetric key authentication. An authenticated client (A) could use this flaw to modify a packet sent between a server (B) and a client (C) using a key that is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on Huawei EulerOS V2.0SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~25.0.1.h1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~25.0.1.h1", rls:"EULEROS-2.0SP1"))) {
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
