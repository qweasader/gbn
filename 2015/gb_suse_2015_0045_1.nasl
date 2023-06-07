# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850770");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-10-13 15:19:50 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094",
                "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098",
                "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for xorg-x11-server (SUSE-SU-2015:0045-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The XOrg X11 server was updated to fix 12 security issues:

  * Denial of service due to unchecked malloc in client authentication
  (CVE-2014-8091).

  * Integer overflows calculating memory needs for requests
  (CVE-2014-8092).

  * Integer overflows calculating memory needs for requests in GLX
  extension (CVE-2014-8093).

  * Integer overflows calculating memory needs for requests in DRI2
  extension (CVE-2014-8094).

  * Out of bounds access due to not validating length or offset values
  in requests in XInput extension (CVE-2014-8095).

  * Out of bounds access due to not validating length or offset values
  in requests in XC-MISC extension (CVE-2014-8096).

  * Out of bounds access due to not validating length or offset values
  in requests in DBE extension (CVE-2014-8097).

  * Out of bounds access due to not validating length or offset values
  in requests in GLX extension (CVE-2014-8098).

  * Out of bounds access due to not validating length or offset values
  in requests in XVideo extension (CVE-2014-8099).

  * Out of bounds access due to not validating length or offset values
  in requests in Render extension (CVE-2014-8100).

  * Out of bounds access due to not validating length or offset values
  in requests in RandR extension (CVE-2014-8101).

  * Out of bounds access due to not validating length or offset values
  in requests in XFixes extension (CVE-2014-8102).

  Additionally, these non-security issues were fixed:

  * Fix crash in RENDER protocol, PanoramiX wrappers (bnc#864911).

  * Some formats used for pictures did not work with the chosen
  framebuffer format (bnc#886213).");

  script_tag(name:"affected", value:"xorg-x11-server on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:0045-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.4~27.101.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.4~27.101.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.4~27.101.1", rls:"SLES11.0SP3"))) {
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
