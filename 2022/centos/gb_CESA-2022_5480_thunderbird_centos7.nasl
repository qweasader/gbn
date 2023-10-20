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
  script_oid("1.3.6.1.4.1.25623.1.0.884225");
  script_version("2023-10-18T05:05:17+0000");
  script_cve_id("CVE-2022-2200", "CVE-2022-2226", "CVE-2022-31744", "CVE-2022-34468", "CVE-2022-34470", "CVE-2022-34472", "CVE-2022-34479", "CVE-2022-34481", "CVE-2022-34484");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 15:52:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-08-03 01:01:20 +0000 (Wed, 03 Aug 2022)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2022:5480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:5480");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-August/073623.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2022:5480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 91.11.

Security Fix(es):

  * Mozilla: CSP sandbox header without `allow-scripts` can be bypassed via
retargeted javascript: URI (CVE-2022-34468)

  * Mozilla: Use-after-free in nsSHistory (CVE-2022-34470)

  * Mozilla: A popup window could be resized in a way to overlay the address
bar with web content (CVE-2022-34479)

  * Mozilla: Memory safety bugs fixed in Firefox 102 and Firefox ESR 91.11
(CVE-2022-34484)

  * Mozilla: Undesired attributes could be set as part of prototype pollution
(CVE-2022-2200)

  * Mozilla: An email with a mismatching OpenPGP signature date was accepted
as valid (CVE-2022-2226)

  * Mozilla: CSP bypass enabling stylesheet injection (CVE-2022-31744)

  * Mozilla: Unavailable PAC file resulted in OCSP requests being blocked
(CVE-2022-34472)

  * Mozilla: Potential integer overflow in ReplaceElementsAt (CVE-2022-34481)

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~91.11.0~2.el7.centos", rls:"CentOS7"))) {
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