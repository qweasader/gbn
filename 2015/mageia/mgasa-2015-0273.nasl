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
  script_oid("1.3.6.1.4.1.25623.1.0.130105");
  script_cve_id("CVE-2014-0578", "CVE-2015-3114", "CVE-2015-3115", "CVE-2015-3116", "CVE-2015-3117", "CVE-2015-3118", "CVE-2015-3119", "CVE-2015-3120", "CVE-2015-3121", "CVE-2015-3122", "CVE-2015-3123", "CVE-2015-3124", "CVE-2015-3125", "CVE-2015-3126", "CVE-2015-3127", "CVE-2015-3128", "CVE-2015-3129", "CVE-2015-3130", "CVE-2015-3131", "CVE-2015-3132", "CVE-2015-3133", "CVE-2015-3134", "CVE-2015-3135", "CVE-2015-3136", "CVE-2015-3137", "CVE-2015-4428", "CVE-2015-4429", "CVE-2015-4430", "CVE-2015-4431", "CVE-2015-4432", "CVE-2015-4433", "CVE-2015-5116", "CVE-2015-5117", "CVE-2015-5118", "CVE-2015-5119");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:45 +0000 (Thu, 15 Oct 2015)");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0273)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0273");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0273.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16325");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-16.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0273 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.481 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow an
attacker to take control of the affected system.

Adobe is aware of a report that an exploit targeting CVE-2015-5119 has
been publicly published.

This updates resolves heap buffer overflow vulnerabilities that could lead
to code execution (CVE-2015-3135, CVE-2015-4432, CVE-2015-5118).

This updates resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2015-3117, CVE-2015-3123, CVE-2015-3130,
CVE-2015-3133, CVE-2015-3134, CVE-2015-4431).

This updates resolves null pointer dereference issues (CVE-2015-3126,
CVE-2015-4429).

This updates resolves a security bypass vulnerability that could lead to
information disclosure (CVE-2015-3114).

This updates resolves type confusion vulnerabilities that could lead to
code execution (CVE-2015-3119, CVE-2015-3120, CVE-2015-3121,
CVE-2015-3122, CVE-2015-4433).

This updates resolves use-after-free vulnerabilities that could lead to
code execution (CVE-2015-3118, CVE-2015-3124, CVE-2015-5117,
CVE-2015-3127, CVE-2015-3128, CVE-2015-3129, CVE-2015-3131, CVE-2015-3132,
CVE-2015-3136, CVE-2015-3137, CVE-2015-4428, CVE-2015-4430, CVE-2015-5119).

This updates resolves vulnerabilities that could be exploited to bypass
the same-origin-policy and lead to information disclosure (CVE-2014-0578,
CVE-2015-3115, CVE-2015-3116, CVE-2015-3125, CVE-2015-5116).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.481~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.481~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.481~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.481~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
