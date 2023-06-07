# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.313.2");
  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-313-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.10");

  script_xref(name:"Advisory-ID", value:"USN-313-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-313-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org2, openoffice.org2-amd64' package(s) announced via the USN-313-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-313-1 fixed several vulnerabilities in OpenOffice for Ubuntu 5.04 and
Ubuntu 6.06 LTS. This followup advisory provides the corresponding
update for Ubuntu 5.10.

For reference, these are the details of the original USN:

 It was possible to embed Basic macros in documents in a way that
 OpenOffice.org would not ask for confirmation about executing them. By
 tricking a user into opening a malicious document, this could be
 exploited to run arbitrary Basic code (including local file access and
 modification) with the user's privileges. (CVE-2006-2198)

 A flaw was discovered in the Java sandbox which allowed Java applets
 to break out of the sandbox and execute code without restrictions. By
 tricking a user into opening a malicious document, this could be
 exploited to run arbitrary code with the user's privileges. This
 update disables Java applets for OpenOffice.org, since it is not
 generally possible to guarantee the sandbox restrictions.
 (CVE-2006-2199)

 A buffer overflow has been found in the XML parser. By tricking a user
 into opening a specially crafted XML file with OpenOffice.org, this
 could be exploited to execute arbitrary code with the user's
 privileges. (CVE-2006-3117)");

  script_tag(name:"affected", value:"'openoffice.org2, openoffice.org2-amd64' package(s) on Ubuntu 5.10.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org2-common", ver:"1.9.129-0.1ubuntu4.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org2-core", ver:"1.9.129-0.1ubuntu4.1", rls:"UBUNTU5.10"))) {
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
