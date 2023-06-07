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
  script_oid("1.3.6.1.4.1.25623.1.0.123702");
  script_cve_id("CVE-2011-2504");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:26 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T07:50:33+0000");
  script_tag(name:"last_modification", value:"2022-04-05 07:50:33 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0502)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0502");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0502.html");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-apps, xorg-x11-server-utils, xorg-x11-utils' package(s) announced via the ELSA-2013-0502 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xorg-x11-apps
[7.6-6]
- x11perf 1.5.4 (CVE-2011-2504)

[7.6-5]
- Rebuilt for [link moved to references]

[7.6-4]
- Move xinput and xkill to xorg-x11-server-utils

[7.6-3]
- Rebuild for libpng 1.5

[7.6-2]
- Rebuilt for [link moved to references]

[7.6-1]
- x11perf 1.5.3

[7.5-5]
- xeyes 1.1.1

[7.5-4]
- xinput 1.5.3
- xkill 1.0.3

[7.5-3]
- xclipboard 1.1.1

[7.5-2]
- o'clock 1.0.2
- xclock 1.0.5
- xconsole 1.0.4
- xbiff 1.0.2
- luit 1.1.0
- x11perf 1.5.2
- xcursorgen 1.0.4
- xeyes 1.1.0
- xload 1.1.0
- xlogo 1.0.3
- xmag 1.0.4
- xmessage 1.0.3
- xfd 1.1.0
- xfontsel 1.0.3
- xvidtune 1.0.2

[7.5-1]
- xwd 1.0.4
- xwud 1.0.3

[7.4-14]
- xinput 1.5.2

[7.4-13]
- xinput 1.5.1

[7.4-12]
- Add missing BR xorg-x11-xbitmaps

[7.4-11]
- Don't steal directory owned by filesystem package

xorg-x11-server-utils
[7.5-13]
- xinput 1.6.0

[7.5-12]
- Add libXinerama-devel requires for new xinput

[7.5-11]
- xinput 1.5.99.901

[7.5-10]
- Rebuilt for [link moved to references]

[7.5-9]
- xinput 1.5.4

[7.5-8]
- Move xinput and xkill here from xorg-x11-apps

[7.5-7]
- Fix BuildRequires ... xbitmaps-devel does not exist anymore (RHBZ #744751)
- Upgrade to the latest upstream iceauth, rgb, sessreg, and xrandr

[7.5-6]
- xset 1.2.2

xorg-x11-utils
[7.5-6]
- Rebuilt for [link moved to references]

[7.5-5]
- xlsclients 1.1.2
- Rebuild for new xcb-util

[7.5-4]
- xdpyinfo 1.3.0

[7.5-3]
- xprop 1.2.1

[7.5-2]
- Rebuilt for [link moved to references]

[7.5-1]
- xvinfo 1.1.1
- xev 1.1.0
- xdpyinfo 1.2.0
- xwininfo 1.1.0
- xlsclients 1.1.0
- xlsfonts 1.0.3

[7.4-10]
- xlsatoms 1.1.0
- xlsclients 1.1.0

[7.4-9]
- edid-decode snapshot");

  script_tag(name:"affected", value:"'xorg-x11-apps, xorg-x11-server-utils, xorg-x11-utils' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-apps", rpm:"xorg-x11-apps~7.6~6.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-utils", rpm:"xorg-x11-server-utils~7.5~13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-utils", rpm:"xorg-x11-utils~7.5~6.el6", rls:"OracleLinux6"))) {
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
