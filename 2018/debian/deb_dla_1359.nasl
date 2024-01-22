# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891359");
  script_cve_id("CVE-2017-17742", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_tag(name:"creation_date", value:"2018-04-24 22:00:00 +0000 (Tue, 24 Apr 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-21 12:15:00 +0000 (Sun, 21 Jul 2019)");

  script_name("Debian: Security Advisory (DLA-1359-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1359-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1359-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.8' package(s) announced via the DLA-1359-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in the interpreter for the Ruby language. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-17742

Aaron Patterson reported that WEBrick bundled with Ruby was vulnerable to an HTTP response splitting vulnerability. It was possible for an attacker to inject fake HTTP responses if a script accepted an external input and output it without modifications.

CVE-2018-6914

ooooooo_q discovered a directory traversal vulnerability in the Dir.mktmpdir method in the tmpdir library. It made it possible for attackers to create arbitrary directories or files via a .. (dot dot) in the prefix argument.

CVE-2018-8777

Eric Wong reported an out-of-memory DoS vulnerability related to a large request in WEBrick bundled with Ruby.

CVE-2018-8778

aerodudrizzt found a buffer under-read vulnerability in the Ruby String#unpack method. If a big number was passed with the specifier @, the number was treated as a negative value, and an out-of-buffer read occurred. Attackers could read data on heaps if an script accepts an external input as the argument of String#unpack.

CVE-2018-8779

ooooooo_q reported that the UNIXServer.open and UNIXSocket.open methods of the socket library bundled with Ruby did not check for NUL bytes in the path argument. The lack of check made the methods vulnerable to unintentional socket creation and unintentional socket access.

CVE-2018-8780

ooooooo_q discovered an unintentional directory traversal in some methods in Dir, by the lack of checking for NUL bytes in their parameter.

For Debian 7 Wheezy, these problems have been fixed in version 1.8.7.358-7.1+deb7u6.

We recommend that you upgrade your ruby1.8 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-full", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7"))) {
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
