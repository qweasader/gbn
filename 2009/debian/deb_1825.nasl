# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64358");
  script_cve_id("CVE-2009-2288");
  script_tag(name:"creation_date", value:"2009-07-06 18:36:15 +0000 (Mon, 06 Jul 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1825-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1825-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1825");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nagios2, nagios3' package(s) announced via the DSA-1825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the statuswml.cgi script of nagios, a monitoring and management system for hosts, services and networks, is prone to a command injection vulnerability. Input to the ping and traceroute parameters of the script is not properly validated which allows an attacker to execute arbitrary shell commands by passing a crafted value to these parameters.

For the oldstable distribution (etch), this problem has been fixed in version 2.6-2+etch3 of nagios2.

For the stable distribution (lenny), this problem has been fixed in version 3.0.6-4~lenny2 of nagios3.

For the testing distribution (squeeze), this problem has been fixed in version 3.0.6-5 of nagios3.

For the unstable distribution (sid), this problem has been fixed in version 3.0.6-5 of nagios3.

We recommend that you upgrade your nagios2/nagios3 packages.");

  script_tag(name:"affected", value:"'nagios2, nagios3' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"nagios2", ver:"2.6-2+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios2-common", ver:"2.6-2+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios2-dbg", ver:"2.6-2+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios2-doc", ver:"2.6-2+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"nagios3", ver:"3.0.6-4~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-common", ver:"3.0.6-4~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-dbg", ver:"3.0.6-4~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-doc", ver:"3.0.6-4~lenny2", rls:"DEB5"))) {
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
