# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58644");
  script_cve_id("CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3949", "CVE-2007-3950", "CVE-2007-4727");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");

  script_name("Debian: Security Advisory (DSA-1362)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1362");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1362");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1362");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lighttpd' package(s) announced via the DSA-1362 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in lighttpd, a fast webserver with minimal memory footprint, which could allow the execution of arbitrary code via the overflow of CGI variables when mod_fcgi was enabled. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3946

The use of mod_auth could leave to a denial of service attack crashing the webserver.

CVE-2007-3947

The improper handling of repeated HTTP headers could cause a denial of service attack crashing the webserver.

CVE-2007-3949

A bug in mod_access potentially allows remote users to bypass access restrictions via trailing slash characters.

CVE-2007-3950

On 32-bit platforms users may be able to create denial of service attacks, crashing the webserver, via mod_webdav, mod_fastcgi, or mod_scgi.

For the stable distribution (etch), these problems have been fixed in version 1.4.13-4etch4.

For the unstable distribution (sid), these problems have been fixed in version 1.4.16-1.

We recommend that you upgrade your lighttpd package.");

  script_tag(name:"affected", value:"'lighttpd' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.13-4etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.13-4etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.13-4etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.13-4etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.13-4etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.13-4etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.13-4etch4", rls:"DEB4"))) {
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
