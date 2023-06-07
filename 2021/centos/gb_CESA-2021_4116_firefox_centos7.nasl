# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883390");
  script_version("2021-12-15T03:03:38+0000");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-38506", "CVE-2021-38507", "CVE-2021-38508", "CVE-2021-38509");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-15 03:03:38 +0000 (Wed, 15 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 19:53:00 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 02:02:07 +0000 (Thu, 18 Nov 2021)");
  script_name("CentOS: Security Advisory for firefox (CESA-2021:4116)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:4116");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-November/048400.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2021:4116 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 91.3.0 ESR.

Security Fix(es):

  * Mozilla: Use-after-free in HTTP2 Session object

  * Mozilla: Memory safety bugs fixed in Firefox 94 and Firefox ESR 91.3

  * Mozilla: iframe sandbox rules did not apply to XSLT stylesheets
(CVE-2021-38503)

  * Mozilla: Use-after-free in file picker dialog (CVE-2021-38504)

  * Mozilla: Firefox could be coaxed into going into fullscreen mode without
notification or warning (CVE-2021-38506)

  * Mozilla: Opportunistic Encryption in HTTP2 could be used to bypass the
Same-Origin-Policy on services hosted on other ports (CVE-2021-38507)

  * Mozilla: Permission Prompt could be overlaid, resulting in user confusion
and potential spoofing (CVE-2021-38508)

  * Mozilla: Javascript alert box could have been spoofed onto an arbitrary
domain (CVE-2021-38509)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'firefox' package(s) on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~91.3.0~1.el7.centos", rls:"CentOS7"))) {
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