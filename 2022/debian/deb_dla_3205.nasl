# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893205");
  script_cve_id("CVE-2019-0053", "CVE-2021-40491", "CVE-2022-39028");
  script_tag(name:"creation_date", value:"2022-11-26 02:00:12 +0000 (Sat, 26 Nov 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-29 00:27:00 +0000 (Tue, 29 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-3205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3205-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3205-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/inetutils");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'inetutils' package(s) announced via the DLA-3205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in inetutils, a collection of common network programs.

CVE-2019-0053

inetutils' telnet client doesn't sufficiently validate environment variables, which can lead to stack-based buffer overflows. This issue is limited to local exploitation from restricted shells.

CVE-2021-40491

inetutils' ftp client before 2.2 does not validate addresses returned by PASV/LSPV responses to make sure they match the server address. A malicious server can exploit this flaw to reach services in the client's private network. (This is similar to curl's CVE-2020-8284.)

CVE-2022-39028

inetutils's telnet server through 2.3 has a NULL pointer dereference which a client can trigger by sending 0xff 0xf7 or 0xff 0xf8. In a typical installation, the telnetd application would crash but the telnet service would remain available through inetd. However, if the telnetd application has many crashes within a short time interval, the telnet service would become unavailable after inetd logs a 'telnet/tcp server failing (looping), service terminated' error.

For Debian 10 buster, these problems have been fixed in version 2:1.9.4-7+deb10u2.

We recommend that you upgrade your inetutils packages.

For the detailed security status of inetutils please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'inetutils' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftp", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftpd", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-inetd", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ping", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-syslogd", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-talk", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-talkd", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-telnet", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-telnetd", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-tools", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-traceroute", ver:"2:1.9.4-7+deb10u2", rls:"DEB10"))) {
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
