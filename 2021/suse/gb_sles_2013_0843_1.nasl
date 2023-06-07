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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0843.1");
  script_cve_id("CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0799", "CVE-2013-0800");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0843-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0843-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130843-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2013:0843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox has been updated to the 17.0.6ESR security release.

 *

 MFSA 2013-30: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 Olli Pettay, Jesse Ruderman, Boris Zbarsky, Christian Holler, Milan Sreckovic, and Joe Drew reported memory safety problems and crashes that affect Firefox ESR 17, and Firefox 19. (CVE-2013-0788)

 *

 MFSA 2013-31 / CVE-2013-0800: Security researcher Abhishek Arya (Inferno) of the Google Chrome Security Team used the Address Sanitizer tool to discover an out-of-bounds write in Cairo graphics library. When certain values are passed to it during rendering, Cairo attempts to use negative boundaries or sizes for boxes, leading to a potentially exploitable crash in some instances.

 *

 MFSA 2013-32 / CVE-2013-0799: Security researcher Frederic Hoguin discovered that the Mozilla Maintenance Service on Windows was vulnerable to a buffer overflow.
This system is used to update software without invoking the User Account Control (UAC) prompt. The Mozilla Maintenance Service is configured to allow unprivileged users to start it with arbitrary arguments. By manipulating the data passed in these arguments, an attacker can execute arbitrary code with the system privileges used by the service. This issue requires local file system access to be exploitable.

 *

 MFSA 2013-34 / CVE-2013-0797: Security researcher Ash reported an issue with the Mozilla Updater. The Mozilla Updater can be made to load a malicious local DLL file in a privileged context through either the Mozilla Maintenance Service or independently on systems that do not use the service. This occurs when the DLL file is placed in a specific location on the local system before the Mozilla Updater is run. Local file system access is necessary in order for this issue to be exploitable.

 *

 MFSA 2013-35 / CVE-2013-0796: Security researcher miaubiz used the Address Sanitizer tool to discover a crash in WebGL rendering when memory is freed that has not previously been allocated. This issue only affects Linux users who have Intel Mesa graphics drivers. The resulting crash could be potentially exploitable.

 *

 MFSA 2013-36 / CVE-2013-0795: Security researcher Cody Crews reported a mechanism to use the cloneNode method to bypass System Only Wrappers (SOW) and clone a protected node. This allows violation of the browser's same origin policy and could also lead to privilege escalation and the execution of arbitrary code.

 *

 MFSA 2013-37 / CVE-2013-0794: Security researcher shutdown reported a method for removing the origin indication on tab-modal dialog boxes in combination with browser navigation. This could allow ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.6esr~0.8.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.6esr~0.8.1", rls:"SLES10.0SP4"))) {
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
