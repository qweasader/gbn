# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840986");
  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460");
  script_tag(name:"creation_date", value:"2012-04-23 06:24:01 +0000 (Mon, 23 Apr 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1400-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1400-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1400-5");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/956961");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gsettings-desktop-schemas' package(s) announced via the USN-1400-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1400-1 fixed vulnerabilities in Firefox. Firefox 11 started using
GSettings to access the system proxy settings. If there is a GSettings
proxy settings schema, Firefox will consume it. The GSettings proxy
settings schema that was shipped by default was unused by other
applications and broke Firefox's ability to use system proxy settings. This
update removes the unused schema. We apologize for the inconvenience.

Original advisory details:

 Soroush Dalili discovered that Firefox did not adequately protect against
 dropping JavaScript links onto a frame. A remote attacker could, through
 cross-site scripting (XSS), exploit this to modify the contents or steal
 confidential data. (CVE-2012-0455)

 Atte Kettunen discovered a use-after-free vulnerability in Firefox's
 handling of SVG animations. An attacker could potentially exploit this to
 execute arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2012-0457)

 Atte Kettunen discovered an out of bounds read vulnerability in Firefox's
 handling of SVG Filters. An attacker could potentially exploit this to make
 data from the user's memory accessible to the page content. (CVE-2012-0456)

 Mike Brooks discovered that using carriage return line feed (CRLF)
 injection, one could introduce a new Content Security Policy (CSP) rule
 which allows for cross-site scripting (XSS) on sites with a separate header
 injection vulnerability. With cross-site scripting vulnerabilities, if a
 user were tricked into viewing a specially crafted page, a remote attacker
 could exploit this to modify the contents, or steal confidential data,
 within the same domain. (CVE-2012-0451)

 Mariusz Mlynski discovered that the Home button accepted JavaScript links
 to set the browser Home page. An attacker could use this vulnerability to
 get the script URL loaded in the privileged about:sessionrestore context.
 (CVE-2012-0458)

 Daniel Glazman discovered that the Cascading Style Sheets (CSS)
 implementation is vulnerable to crashing due to modification of a keyframe
 followed by access to the cssText of the keyframe. If the user were tricked
 into opening a specially crafted web page, an attacker could exploit this
 to cause a denial of service via application crash, or potentially execute
 code with the privileges of the user invoking Firefox. (CVE-2012-0459)

 Matt Brubeck discovered that Firefox did not properly restrict access to
 the window.fullScreen object. If the user were tricked into opening a
 specially crafted web page, an attacker could potentially use this
 vulnerability to spoof the user interface. (CVE-2012-0460)

 Bob Clary, Christian Holler, Jesse Ruderman, Michael Bebenita, David
 Anderson, Jeff Walden, Vincenzo Iozzo, and Willem Pinckaers discovered
 memory safety issues affecting Firefox. If the user were tricked into
 opening a specially crafted page, an attacker could exploit these to
 cause a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gsettings-desktop-schemas' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"gsettings-desktop-schemas", ver:"3.0.0-0ubuntu1.1", rls:"UBUNTU11.04"))) {
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
