# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2004.20.1");
  script_cve_id("CVE-2004-0983");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-20-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-20-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-20-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.8' package(s) announced via the USN-20-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Ruby developers discovered a potential Denial of Service
vulnerability in the CGI module (cgi.rb). Specially crafted CGI
requests could cause an infinite loop in the server process.
Repetitive attacks could use most of the available processor
resources, exhaust the number of allowed parallel connections in web
servers, or cause similar effects which render the service
unavailable.

There is no possibility of privilege escalation or data loss.");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbigdecimal-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurses-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdl-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdrb-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liberb-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiconv-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpty-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libracc-runtime-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librexml-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdbm-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsoap-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrscan-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsyslog-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtest-unit-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtk-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebrick-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libyaml-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzlib-ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.1+1.8.2pre2-3ubuntu0.1", rls:"UBUNTU4.10"))) {
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
