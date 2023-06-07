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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1153.1");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1697");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1153-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131153-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2013:1153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox has been updated to the 17.0.7 ESR version,
which fixes bugs and security issues.

 *

 MFSA 2013-49: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 Gary Kwong, Jesse Ruderman, and Andrew McCreight reported memory safety problems and crashes that affect Firefox ESR 17, and Firefox 21. (CVE-2013-1682)

 *

 MFSA 2013-50: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team used the Address Sanitizer tool to discover a series of use-after-free problems rated critical as security issues in shipped software. Some of these issues are potentially exploitable, allowing for remote code execution. We would also like to thank Abhishek for reporting additional use-after-free and buffer overflow flaws in code introduced during Firefox development. These were fixed before general release.

 o Heap-use-after-free in mozilla::dom::HTMLMediaElement::LookupMediaElementURITable
(CVE-2013-1684) o Heap-use-after-free in nsIDocument::GetRootElement (CVE-2013-1685) o Heap-use-after-free in mozilla::ResetDir (CVE-2013-1686)
 *

 MFSA 2013-51 / CVE-2013-1687: Security researcher Mariusz Mlynski reported that it is possible to compile a user-defined function in the XBL scope of a specific element and then trigger an event within this scope to run code. In some circumstances, when this code is run, it can access content protected by System Only Wrappers (SOW) and chrome-privileged pages. This could potentially lead to arbitrary code execution. Additionally, Chrome Object Wrappers (COW) can be bypassed by web content to access privileged methods, leading to a cross-site scripting (XSS)
attack from privileged pages.

 *

 MFSA 2013-53 / CVE-2013-1690: Security researcher Nils reported that specially crafted web content using the onreadystatechange event and reloading of pages could sometimes cause a crash when unmapped memory is executed.
This crash is potentially exploitable.

 *

 MFSA 2013-54 / CVE-2013-1692: Security researcher Johnathan Kuskos reported that Firefox is sending data in the body of XMLHttpRequest (XHR) HEAD requests, which goes agains the XHR specification. This can potentially be used for Cross-Site Request Forgery (CSRF) attacks against sites which do not distinguish between HEAD and POST requests.

 *

 MFSA 2013-55 / CVE-2013-1693: Security researcher Paul Stone of Context Information Security discovered that timing differences in the processing of SVG format images with filters could allow for pixel values to be read. This could potentially allow for text values to be read across domains, leading to information disclosure.

 *

 MFSA 2013-59 / ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.7esr~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.10.28", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.7esr~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.7esr~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.6.9.31", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.7esr~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.7esr~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.6.9.31", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.7esr~0.3.1", rls:"SLES11.0SP2"))) {
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
