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
  script_oid("1.3.6.1.4.1.25623.1.0.71478");
  script_cve_id("CVE-2012-1118", "CVE-2012-1119", "CVE-2012-1120", "CVE-2012-1122", "CVE-2012-1123", "CVE-2012-2692");
  script_tag(name:"creation_date", value:"2012-08-10 07:06:58 +0000 (Fri, 10 Aug 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2500");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2500");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2500");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mantis' package(s) announced via the DSA-2500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Mantis, an issue tracking system.

CVE-2012-1118

Mantis installation in which the private_bug_view_threshold configuration option has been set to an array value do not properly enforce bug viewing restrictions.

CVE-2012-1119

Copy/clone bug report actions fail to leave an audit trail.

CVE-2012-1120

The delete_bug_threshold/bugnote_allow_user_edit_delete access check can be bypassed by users who have write access to the SOAP API.

CVE-2012-1122

Mantis performed access checks incorrectly when moving bugs between projects.

CVE-2012-1123

A SOAP client sending a null password field can authenticate as the Mantis administrator.

CVE-2012-2692

Mantis does not check the delete_attachments_threshold permission when a user attempts to delete an attachment from an issue.

For the stable distribution (squeeze), these problems have been fixed in version 1.1.8+dfsg-10squeeze2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 1.2.11-1.

We recommend that you upgrade your mantis packages.");

  script_tag(name:"affected", value:"'mantis' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mantis", ver:"1.1.8+dfsg-10squeeze2", rls:"DEB6"))) {
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
