# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55591");
  script_cve_id("CVE-2005-2337");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-862-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-862-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-862-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-862");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.6' package(s) announced via the DSA-862-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yutaka Oiwa discovered a bug in Ruby, the interpreter for the object-oriented scripting language, that can cause illegal program code to bypass the safe level and taint flag protections check and be executed. The following matrix lists the fixed versions in our distributions:



old stable (woody)

stable (sarge)

unstable (sid)

ruby

1.6.7-3woody5

n/a

n/a

ruby1.6

n/a

1.6.8-12sarge1

1.6.8-13

ruby1.8

n/a

1.8.2-7sarge2

1.8.3-1

We recommend that you upgrade your ruby packages.");

  script_tag(name:"affected", value:"'ruby1.6' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"irb1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurses-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbm-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdbm-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpty-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreadline-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.6-dbg", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdbm-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsyslog-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtk-ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.6", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.6-dev", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.6-elisp", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.6-examples", ver:"1.6.8-12sarge1", rls:"DEB3.1"))) {
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
