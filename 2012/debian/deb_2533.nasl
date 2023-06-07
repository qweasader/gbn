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
  script_oid("1.3.6.1.4.1.25623.1.0.71821");
  script_cve_id("CVE-2012-3418", "CVE-2012-3419", "CVE-2012-3420", "CVE-2012-3421");
  script_tag(name:"creation_date", value:"2012-08-30 15:32:31 +0000 (Thu, 30 Aug 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2533");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2533");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2533");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pcp' package(s) announced via the DSA-2533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Performance Co-Pilot (pcp), a framework for performance monitoring, contains several vulnerabilities.

CVE-2012-3418

Multiple buffer overflows in the PCP protocol decoders can cause PCP clients and servers to crash or, potentially, execute arbitrary code while processing crafted PDUs.

CVE-2012-3419

The linux PMDA used by the pmcd daemon discloses sensitive information from the /proc file system to unauthenticated clients.

CVE-2012-3420

Multiple memory leaks processing crafted requests can cause pmcd to consume large amounts of memory and eventually crash.

CVE-2012-3421

Incorrect event-driven programming allows malicious clients to prevent other clients from accessing the pmcd daemon.

To address the information disclosure vulnerability, CVE-2012-3419, a new proc PMDA was introduced, which is disabled by default. If you need access to this information, you need to enable the proc PMDA.

For the stable distribution (squeeze), this problem has been fixed in version 3.3.3-squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 3.6.5.

We recommend that you upgrade your pcp packages.");

  script_tag(name:"affected", value:"'pcp' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-gui2-dev", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-gui2", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-logsummary-perl", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-mmv-perl", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-mmv1-dev", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-mmv1", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-pmda-perl", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-pmda3-dev", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-pmda3", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-trace2-dev", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp-trace2", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp3-dev", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcp3", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcp", ver:"3.3.3-squeeze2", rls:"DEB6"))) {
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
