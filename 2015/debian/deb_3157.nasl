# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703157");
  script_cve_id("CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090");
  script_tag(name:"creation_date", value:"2015-02-08 23:00:00 +0000 (Sun, 08 Feb 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3157)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3157");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3157");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3157");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.9.1' package(s) announced via the DSA-3157 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the interpreter for the Ruby language:

CVE-2014-4975

The encodes() function in pack.c had an off-by-one error that could lead to a stack-based buffer overflow. This could allow remote attackers to cause a denial of service (crash) or arbitrary code execution.

CVE-2014-8080, CVE-2014-8090 The REXML parser could be coerced into allocating large string objects that could consume all available memory on the system. This could allow remote attackers to cause a denial of service (crash).

For the stable distribution (wheezy), these problems have been fixed in version 1.9.3.194-8.1+deb7u3.

For the upcoming stable distribution (jessie), these problems have been fixed in version 2.1.5-1 of the ruby2.1 source package.

For the unstable distribution (sid), these problems have been fixed in version 2.1.5-1 of the ruby2.1 source package.

We recommend that you upgrade your ruby1.9.1 packages.");

  script_tag(name:"affected", value:"'ruby1.9.1' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1-dbg", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.9.1", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.9.1", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-dev", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-examples", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-full", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.3", ver:"1.9.3.194-8.1+deb7u3", rls:"DEB7"))) {
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
