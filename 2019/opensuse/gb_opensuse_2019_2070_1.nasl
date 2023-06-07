# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852693");
  script_version("2022-06-29T10:11:11+0000");
  script_cve_id("CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-13616", "CVE-2019-5051", "CVE-2019-5052", "CVE-2019-5057", "CVE-2019-5058", "CVE-2019-5059", "CVE-2019-5060");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-29 10:11:11 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:29:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2019-09-06 02:01:05 +0000 (Fri, 06 Sep 2019)");
  script_name("openSUSE: Security Advisory for SDL2_image (openSUSE-SU-2019:2070-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:2070-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00012.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2_image'
  package(s) announced via the openSUSE-SU-2019:2070-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2_image fixes the following issues:

  Update to new upstream release 2.0.5.

  Security issues fixed:

  * TALOS-2019-0820 CVE-2019-5051: exploitable heap-based buffer overflow
  vulnerability when loading a PCX file (boo#1140419)

  * TALOS-2019-0821 CVE-2019-5052: exploitable integer overflow
  vulnerability when loading a PCX file (boo#1140421)

  * TALOS-2019-0841 CVE-2019-5057: code execution vulnerability in the PCX
  image-rendering functionality of SDL2_image (boo#1143763)

  * TALOS-2019-0842 CVE-2019-5058: heap overflow in XCF image rendering can
  lead to code execution (boo#1143764)

  * TALOS-2019-0843 CVE-2019-5059: heap overflow in XPM image (boo#1143766)

  * TALOS-2019-0844 CVE-2019-5060: integer overflow in the XPM image
  (boo#1143768)

  Not mentioned by upstream, but issues seemingly further fixed:

  * CVE-2019-12218: NULL pointer dereference in the SDL2_image function
  IMG_LoadPCX_RW (boo#1135789)

  * CVE-2019-12217: NULL pointer dereference in the SDL stdio_read function
  (boo#1135787)

  * CVE-2019-12220: SDL_image triggers an out-of-bounds read in the SDL
  function SDL_FreePalette_REAL (boo#1135806)

  * CVE-2019-12221: a SEGV caused by SDL_image in SDL function SDL_free_REAL
  in stdlib/SDL_malloc.c (boo#1135796)

  * CVE-2019-12222: out-of-bounds read triggered by SDL_image in the
  function SDL_InvalidateMap at video/SDL_pixels.c (boo#1136101)

  * CVE-2019-13616: fix heap buffer overflow when reading a crafted bmp file
  (boo#1141844).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2070=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2070=1");

  script_tag(name:"affected", value:"'SDL2_image' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2_image-debugsource", rpm:"SDL2_image-debugsource~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_image-2_0-0", rpm:"libSDL2_image-2_0-0~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_image-2_0-0-debuginfo", rpm:"libSDL2_image-2_0-0-debuginfo~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_image-devel", rpm:"libSDL2_image-devel~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_image-2_0-0-32bit", rpm:"libSDL2_image-2_0-0-32bit~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_image-2_0-0-32bit-debuginfo", rpm:"libSDL2_image-2_0-0-32bit-debuginfo~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_image-devel-32bit", rpm:"libSDL2_image-devel-32bit~2.0.5~lp150.9.1", rls:"openSUSELeap15.0"))) {
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
