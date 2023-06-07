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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2019.141.01");
  script_cve_id("CVE-2018-18511", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11694", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818", "CVE-2019-9819", "CVE-2019-9820");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 16:15:00 +0000 (Fri, 26 Jul 2019)");

  script_name("Slackware: Security Advisory (SSA:2019-141-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2019-141-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2019&m=slackware-security.480262");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2018-18511");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-11691");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-11692");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-11693");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-11694");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-11698");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-5798");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-7317");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9797");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9800");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9815");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9816");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9817");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9818");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9819");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/#CVE-2019-9820");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/known-vulnerabilities/firefoxESR.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2019-141-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 14.2 and -current to
fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-60.7.0esr-i686-1_slack14.2.txz: Upgraded.
 This release contains security fixes and improvements. Some of the patched
 flaws are considered critical, and could be used to run attacker code and
 install software, requiring no user interaction beyond normal browsing.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]#CVE-2019-9815
 [link moved to references]#CVE-2019-9816
 [link moved to references]#CVE-2019-9817
 [link moved to references]#CVE-2019-9818
 [link moved to references]#CVE-2019-9819
 [link moved to references]#CVE-2019-9820
 [link moved to references]#CVE-2019-11691
 [link moved to references]#CVE-2019-11692
 [link moved to references]#CVE-2019-11693
 [link moved to references]#CVE-2019-7317
 [link moved to references]#CVE-2019-9797
 [link moved to references]#CVE-2018-18511
 [link moved to references]#CVE-2019-11694
 [link moved to references]#CVE-2019-11698
 [link moved to references]#CVE-2019-5798
 [link moved to references]#CVE-2019-9800
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"60.7.0esr-i686-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"60.7.0esr-x86_64-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"60.7.0esr-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"60.7.0esr-x86_64-1", rls:"SLKcurrent"))) {
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
