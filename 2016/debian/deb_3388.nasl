# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703388");
  script_cve_id("CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7855", "CVE-2015-7871");
  script_tag(name:"creation_date", value:"2016-05-06 09:59:25 +0000 (Fri, 06 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 14:19:55 +0000 (Tue, 15 Aug 2017)");

  script_name("Debian: Security Advisory (DSA-3388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3388-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3388-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3388");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DSA-3388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Network Time Protocol daemon and utility programs:

CVE-2015-5146

A flaw was found in the way ntpd processed certain remote configuration packets. An attacker could use a specially crafted package to cause ntpd to crash if:

ntpd enabled remote configuration

The attacker had the knowledge of the configuration password

The attacker had access to a computer entrusted to perform remote configuration

Note that remote configuration is disabled by default in NTP.

CVE-2015-5194

It was found that ntpd could crash due to an uninitialized variable when processing malformed logconfig configuration commands.

CVE-2015-5195

It was found that ntpd exits with a segmentation fault when a statistics type that was not enabled during compilation (e.g. timingstats) is referenced by the statistics or filegen configuration command.

CVE-2015-5219

It was discovered that sntp program would hang in an infinite loop when a crafted NTP packet was received, related to the conversion of the precision value in the packet to double.

CVE-2015-5300

It was found that ntpd did not correctly implement the -g option:

Normally, ntpd exits with a message to the system log if the offset exceeds the panic threshold, which is 1000 s by default. This option allows the time to be set to any value without restriction, however, this can happen only once. If the threshold is exceeded after that, ntpd will exit with a message to the system log. This option can be used with the -q and -x options.

ntpd could actually step the clock multiple times by more than the panic threshold if its clock discipline doesn't have enough time to reach the sync state and stay there for at least one update. If a man-in-the-middle attacker can control the NTP traffic since ntpd was started (or maybe up to 15-30 minutes after that), they can prevent the client from reaching the sync state and force it to step its clock by any amount any number of times, which can be used by attackers to expire certificates, etc.

This is contrary to what the documentation says. Normally, the assumption is that an MITM attacker can step the clock more than the panic threshold only once when ntpd starts and to make a larger adjustment the attacker has to divide it into multiple smaller steps, each taking 15 minutes, which is slow.

CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 It was found that the fix for CVE-2014-9750 was incomplete: three issues were found in the value length checks in ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. Receipt of these packets can cause ntpd to crash.

CVE-2015-7701

A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd is configured to use autokey authentication, an attacker could send packets to ntpd that would, after several days of ongoing attack, cause it to run out of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls:"DEB8"))) {
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
