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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0153");
  script_cve_id("CVE-2020-9759", "CVE-2020-9760");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-25T04:24:37+0000");
  script_tag(name:"last_modification", value:"2022-04-25 04:24:37 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 19:05:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2020-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0153");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0153.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26400");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2157");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'weechat' package(s) announced via the MGASA-2020-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated weechat packages fix security vulnerabilities:

An issue was discovered in WeeChat before 2.7.1 (0.4.0 to 2.7 are
affected). A malformed message 352 (who) can cause a NULL pointer
dereference in the callback function, resulting in a crash
(CVE-2020-9759).

An issue was discovered in WeeChat before 2.7.1 (0.3.4 to 2.7 are
affected). When a new IRC message 005 is received with longer nick
prefixes, a buffer overflow and possibly a crash can happen when a
new mode is set for a nick (CVE-2020-9760).");

  script_tag(name:"affected", value:"'weechat' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"weechat", rpm:"weechat~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-aspell", rpm:"weechat-aspell~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-charset", rpm:"weechat-charset~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-devel", rpm:"weechat-devel~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-guile", rpm:"weechat-guile~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-lua", rpm:"weechat-lua~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-perl", rpm:"weechat-perl~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-python", rpm:"weechat-python~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-ruby", rpm:"weechat-ruby~2.7.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weechat-tcl", rpm:"weechat-tcl~2.7.1~1.mga7", rls:"MAGEIA7"))) {
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
