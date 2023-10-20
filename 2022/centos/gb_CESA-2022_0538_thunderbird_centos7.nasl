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
  script_oid("1.3.6.1.4.1.25623.1.0.884201");
  script_version("2023-10-18T05:05:17+0000");
  script_cve_id("CVE-2022-22754", "CVE-2022-22756", "CVE-2022-22759", "CVE-2022-22760", "CVE-2022-22761", "CVE-2022-22763", "CVE-2022-22764");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-29 22:51:00 +0000 (Thu, 29 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-02-16 02:00:47 +0000 (Wed, 16 Feb 2022)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2022:0538)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:0538");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-February/073558.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2022:0538 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 91.6.0.

Security Fix(es):

  * Mozilla: Extensions could have bypassed permission confirmation during
update (CVE-2022-22754)

  * Mozilla: Memory safety bugs fixed in Firefox 97 and Firefox ESR 91.6
(CVE-2022-22764)

  * Mozilla: Drag and dropping an image could have resulted in the dropped
object being an executable (CVE-2022-22756)

  * Mozilla: Sandboxed iframes could have executed script if the parent
appended elements (CVE-2022-22759)

  * Mozilla: Cross-Origin responses could be distinguished between script and
non-script content-types (CVE-2022-22760)

  * Mozilla: frame-ancestors Content Security Policy directive was not
enforced for framed extension pages (CVE-2022-22761)

  * Mozilla: Script Execution during invalid object state (CVE-2022-22763)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~91.6.0~1.el7.centos", rls:"CentOS7"))) {
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