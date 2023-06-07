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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0248.2");
  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1484", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489", "CVE-2014-1490", "CVE-2014-1491");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-21 18:37:00 +0000 (Fri, 21 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0248-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0248-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140248-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2014:0248-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to the 24.3.0ESR security release.

The following security issues have been fixed:

 *

 MFSA 2014-01: Memory safety bugs fixed in Firefox ESR 24.3 and Firefox 27.0 (CVE-2014-1477)(bnc#862345)

 *

 MFSA 2014-02: Using XBL scopes its possible to steal(clone) native anonymous content
(CVE-2014-1479)(bnc#862348)

 *

 MFSA 2014-03: Download 'open file' dialog delay is too quick, doesn't prevent clickjacking (CVE-2014-1480)

 *

 MFSA 2014-04: Image decoding causing FireFox to crash with Goo Create (CVE-2014-1482)(bnc#862356)

 *

 MFSA 2014-05: caretPositionFromPoint and elementFromPoint leak information about iframe contents via timing information (CVE-2014-1483)(bnc#862360)

 *

 MFSA 2014-06: Fennec leaks profile path to logcat
(CVE-2014-1484)

 *

 MFSA 2014-07: CSP should block XSLT as script, not as style (CVE-2014-1485)

 *

 MFSA 2014-08: imgRequestProxy Use-After-Free Remote Code Execution Vulnerability (CVE-2014-1486)

 *

 MFSA 2014-09: Cross-origin information disclosure with error message of Web Workers (CVE-2014-1487)

 *

 MFSA 2014-10: settings & history ID bug
(CVE-2014-1489)

 *

 MFSA 2014-11: Firefox reproducibly crashes when using asm.js code in workers and transferable objects
(CVE-2014-1488)

 *

 MFSA 2014-12: TOCTOU, potential use-after-free in libssl's session ticket processing
(CVE-2014-1490)(bnc#862300) Do not allow p-1 as a public DH value (CVE-2014-1491)(bnc#862289)

 *

 MFSA 2014-13: Inconsistent this value when invoking getters on window (CVE-2014-1481)(bnc#862309)

Also Mozilla NSS was updated to 3.15.4 release.

 * required for Firefox 27
 * regular CA root store update (1.96)
 * some OSCP improvments
 * other bugfixes

Security Issue references:

 * CVE-2014-1477
>
 * CVE-2014-1479
>
 * CVE-2014-1480
>
 * CVE-2014-1481
>
 * CVE-2014-1482
>
 * CVE-2014-1483
>
 * CVE-2014-1484
>
 * CVE-2014-1485
>
 * CVE-2014-1486
>
 * CVE-2014-1487
>
 * CVE-2014-1488
>
 * CVE-2014-1489
>
 * CVE-2014-1490
>
 * CVE-2014-1491
>");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.3.0esr~0.4.2.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~24~0.4.10.4", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.3.0esr~0.4.2.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1", rpm:"firefox-libgcc_s1~4.7.2_20130108~0.16.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~4.7.2_20130108~0.16.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.15.4~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.15.4~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.2~0.3.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.2~0.3.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.15.4~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.15.4~0.4.2.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.15.4~0.4.2.1", rls:"SLES11.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.3.0esr~0.4.2.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~24~0.4.10.4", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.3.0esr~0.4.2.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1", rpm:"firefox-libgcc_s1~4.7.2_20130108~0.16.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~4.7.2_20130108~0.16.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.15.4~0.4.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.15.4~0.4.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.2~0.3.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.2~0.3.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.15.4~0.4.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.15.4~0.4.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.15.4~0.4.2.1", rls:"SLES11.0SP2"))) {
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
