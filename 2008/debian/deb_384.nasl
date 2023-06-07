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
  script_oid("1.3.6.1.4.1.25623.1.0.53668");
  script_cve_id("CVE-2003-0681", "CVE-2003-0694");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-384");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-384");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-384");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sendmail, sendmail-wide' package(s) announced via the DSA-384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were reported in sendmail.

CAN-2003-0681: A 'potential buffer overflow in ruleset parsing' for Sendmail 8.12.9, when using the nonstandard rulesets (1) recipient (2), final, or (3) mailer-specific envelope recipients, has unknown consequences.

CAN-2003-0694: The prescan function in Sendmail 8.12.9 allows remote attackers to execute arbitrary code via buffer overflow attacks, as demonstrated using the parseaddr function in parseaddr.c.

For the stable distribution (woody) these problems have been fixed in sendmail version 8.12.3-6.6 and sendmail-wide version 8.12.3+3.5Wbeta-5.5.

For the unstable distribution (sid) these problems have been fixed in sendmail version 8.12.10-1.

We recommend that you update your sendmail package.");

  script_tag(name:"affected", value:"'sendmail, sendmail-wide' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sendmail-wide", ver:"8.12.3+3.5Wbeta-5.5", rls:"DEB3.0"))) {
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