# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.71256");
  script_cve_id("CVE-2012-0216");
  script_tag(name:"creation_date", value:"2012-04-30 11:57:31 +0000 (Mon, 30 Apr 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2452)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2452");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2452");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2452");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-2452 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Niels Heinen noticed a security issue with the default Apache configuration on Debian if certain scripting modules like mod_php or mod_rivet are installed. The problem arises because the directory /usr/share/doc, which is mapped to the URL /doc, may contain example scripts that can be executed by requests to this URL. Although access to the URL /doc is restricted to connections from localhost, this still creates security issues in two specific configurations:

if some front-end server on the same host forwards connections to an apache2 backend server on the localhost address, or

if the machine running apache2 is also used for web browsing.

Systems not meeting one of these two conditions are not known to be vulnerable. The actual security impact depends on which packages (and accordingly which example scripts) are installed on the system. Possible issues include cross site scripting, code execution, or leakage of sensitive data.

This updates removes the problematic configuration sections from the files /etc/apache2/sites-available/default and .../default-ssl. When upgrading, you should not blindly allow dpkg to replace those files, though. Rather you should merge the changes, namely the removal of the Alias /doc '/usr/share/doc' line and the related <Directory '/usr/share/doc/'> block, into your versions of these config files. You may also want to check if you have copied these sections to any additional virtual host configurations.

For the stable distribution (squeeze), this problem has been fixed in version 2.2.16-6+squeeze7.

For the testing distribution (wheezy), this problem will be fixed in version 2.2.22-4.

For the unstable distribution (sid), this problem will be fixed in version 2.2.22-4.

For the experimental distribution, this problem has been fixed in version 2.4.1-3.

We recommend that you upgrade your apache2 packages and adjust your configuration.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.2.16-6+squeeze7", rls:"DEB6"))) {
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
