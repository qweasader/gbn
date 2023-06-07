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
  script_oid("1.3.6.1.4.1.25623.1.0.130112");
  script_cve_id("CVE-2015-1266", "CVE-2015-1267", "CVE-2015-1268", "CVE-2015-1269");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:51 +0000 (Thu, 15 Oct 2015)");
  script_version("2022-06-27T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:26 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0265");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0265.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16190");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/06/chrome-stable-update.html");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=786909");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A scheme validation error in WebUI (CVE-2015-1266).

Two cross-origin bypass issues in Blink (CVE-2015-1267, CVE-2015-1268).

A normalization error in the HSTS/HPKP preload list (CVE-2015-1269).

This update also disables the automatic, silent downloading and
installation of 'external components' like the hotword extension.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~43.0.2357.130~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~43.0.2357.130~1.mga4", rls:"MAGEIA4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~43.0.2357.130~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~43.0.2357.130~1.mga5", rls:"MAGEIA5"))) {
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
