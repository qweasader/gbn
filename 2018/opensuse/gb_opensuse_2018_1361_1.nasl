# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851753");
  script_version("2021-06-28T02:00:39+0000");
  script_tag(name:"last_modification", value:"2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-21 05:00:55 +0200 (Mon, 21 May 2018)");
  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5159",
                "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170",
                "CVE-2018-5174", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184",
                "CVE-2018-5185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:44:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Mozilla (openSUSE-SU-2018:1361-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Mozilla Thunderbird to version 52.8 fixes the following
  issues:

  Security issues fixed (MFSA 2018-13, boo#1092548):

  - CVE-2018-5183: Backport critical security fixes in Skia

  - CVE-2018-5154: Use-after-free with SVG animations and clip paths

  - CVE-2018-5155: Use-after-free with SVG animations and text paths

  - CVE-2018-5159: Integer overflow and out-of-bounds write in Skia

  - CVE-2018-5168: Lightweight themes can be installed without user
  interaction

  - CVE-2018-5178: Buffer overflow during UTF-8 to Unicode string conversion
  through legacy extension

  - CVE-2018-5150: Memory safety bugs fixed in Firefox 60, Firefox ESR 52.8,
  and Thunderbird 52.8

  - CVE-2018-5161: Hang via malformed headers (bsc#1093970)

  - CVE-2018-5162: Encrypted mail leaks plaintext through src attribute
  (bsc#1093971)

  - CVE-2018-5170: Filename spoofing for external attachments (bsc#1093972)

  - CVE-2018-5184: Full plaintext recovery in S/MIME via chosen-ciphertext
  attack (bsc#1093969)

  - CVE-2018-5185: Leaking plaintext through HTML forms (bsc#1093973)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-486=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-486=1");

  script_tag(name:"affected", value:"Mozilla on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1361-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00089.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.8~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.8~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.8~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.8~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.8~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.8~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.8~63.1", rls:"openSUSELeap42.3"))) {
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
