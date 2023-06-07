# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.53366");
  script_cve_id("CVE-2003-0205", "CVE-2003-0206");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-294");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-294");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-294");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gkrellm-newsticker' package(s) announced via the DSA-294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brian Campbell discovered two security-related problems in gkrellm-newsticker, a plugin for the gkrellm system monitor program, which provides a news ticker from RDF feeds. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2003-0205

It can launch a web browser of the user's choice when the ticker title is clicked by using the URI given by the feed. However, special shell characters are not properly escaped enabling a malicious feed to execute arbitrary shell commands on the clients machine.

CAN-2003-0206

It crashes the entire gkrellm system on feeds where link or title elements are not entirely on a single line. A malicious server could therefore craft a denial of service.

For the stable distribution (woody) these problems have been fixed in version 0.3-3.1.

The old stable distribution (potato) is not affected since it doesn't contain gkrellm-newsticker packages.

For the unstable distribution (sid) these problems is not yet fixed.

We recommend that you upgrade your gkrellm-newsticker package.");

  script_tag(name:"affected", value:"'gkrellm-newsticker' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"gkrellm-newsticker", ver:"0.3-3.1", rls:"DEB3.0"))) {
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
