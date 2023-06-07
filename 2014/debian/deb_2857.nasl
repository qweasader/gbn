# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702857");
  script_cve_id("CVE-2013-6429", "CVE-2013-6430");
  script_tag(name:"creation_date", value:"2014-02-07 23:00:00 +0000 (Fri, 07 Feb 2014)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-22 16:15:00 +0000 (Wed, 22 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-2857)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2857");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2857");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2857");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libspring-java' package(s) announced via the DSA-2857 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered by the Spring development team that the fix for the XML External Entity (XXE) Injection ( CVE-2013-4152) in the Spring Framework was incomplete.

Spring MVC's SourceHttpMessageConverter also processed user provided XML and neither disabled XML external entities nor provided an option to disable them. SourceHttpMessageConverter has been modified to provide an option to control the processing of XML external entities and that processing is now disabled by default.

In addition Jon Passki discovered a possible XSS vulnerability: The JavaScriptUtils.javaScriptEscape() method did not escape all characters that are sensitive within either a JS single quoted string, JS double quoted string, or HTML script data context. In most cases this will result in an unexploitable parse error but in some cases it could result in an XSS vulnerability.

For the stable distribution (wheezy), these problems have been fixed in version 3.0.6.RELEASE-6+deb7u2.

For the testing distribution (jessie), these problems have been fixed in version 3.0.6.RELEASE-11.

For the unstable distribution (sid), these problems have been fixed in version 3.0.6.RELEASE-11.

We recommend that you upgrade your libspring-java packages.");

  script_tag(name:"affected", value:"'libspring-java' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libspring-aop-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-beans-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-context-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-context-support-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-core-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-expression-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-instrument-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-jdbc-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-jms-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-orm-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-oxm-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-test-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-transaction-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-portlet-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-servlet-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-struts-java", ver:"3.0.6.RELEASE-6+deb7u2", rls:"DEB7"))) {
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
