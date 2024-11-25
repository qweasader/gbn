# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0414");
  script_cve_id("CVE-2016-7426", "CVE-2016-7429", "CVE-2016-9310", "CVE-2016-9311");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-17 17:43:53 +0000 (Tue, 17 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0414)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0414");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0414.html");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#November_2016_ntp_4_2_8p9_NTP_Se");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19843");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1397319");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1397341");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1397345");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1398350");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2016-0414 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When ntpd is configured with rate limiting for all associations (restrict
default limited in ntp.conf), the limits are applied also to responses
received from its configured sources. An attacker who knows the sources
(e.g., from an IPv4 refid in server response) and knows the system is
(mis)configured in this way can periodically send packets with spoofed
source address to keep the rate limiting activated and prevent ntpd from
accepting valid responses from its sources (CVE-2016-7426).

When ntpd receives a server response on a socket that corresponds to a
different interface than was used for the request, the peer structure is
updated to use the interface for new requests. If ntpd is running on a
host with multiple interfaces in separate networks and the operating
system doesn't check source address in received packets (e.g. rp_filter
on Linux is set to 0), an attacker that knows the address of the source
can send a packet with spoofed source address which will cause ntpd to
select wrong interface for the source and prevent it from sending new
requests until the list of interfaces is refreshed, which happens on
routing changes or every 5 minutes by default. If the attack is repeated
often enough (once per second), ntpd will not be able to synchronize
with the source (CVE-2016-7429).

An exploitable configuration modification vulnerability exists in the
control mode (mode 6) functionality of ntpd. If, against long-standing
BCP recommendations, 'restrict default noquery ...' is not specified,
a specially crafted control mode packet can set ntpd traps, providing
information disclosure and DDoS amplification, and unset ntpd traps,
disabling legitimate monitoring. A remote, unauthenticated, network
attacker can trigger this vulnerability (CVE-2016-9310).

If trap service, disabled by default, has been explicitly enabled, an
attacker can send a specially crafted packet to cause a null pointer
dereference that will crash ntpd, resulting in a denial of service
(CVE-2016-9311).");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~24.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~24.7.mga5", rls:"MAGEIA5"))) {
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
