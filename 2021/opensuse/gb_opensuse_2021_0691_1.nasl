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
  script_oid("1.3.6.1.4.1.25623.1.0.853807");
  script_version("2021-08-26T10:01:08+0000");
  script_cve_id("CVE-2020-26664");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-19 15:14:00 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-05-12 03:03:18 +0000 (Wed, 12 May 2021)");
  script_name("openSUSE: Security Advisory for vlc (openSUSE-SU-2021:0691-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0691-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6NFAANEHTTDAXZIGCXPSKGYDFZDQ3HMF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the openSUSE-SU-2021:0691-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vlc fixes the following issues:

     Update to version 3.0.13:

       + Demux:

  - Adaptive: fix artefacts in HLS streams with wrong profiles/levels

  - Fix regression on some MP4 files for the audio track

  - Fix MPGA and ADTS probing in TS files

  - Fix Flac inside AVI files

  - Fix VP9/Webm artefacts when seeking

       + Codec:

  - Support SSA text scaling

  - Fix rotation on Android rotation

  - Fix WebVTT subtitles that start at 00:00

       + Access:

  - Update libnfs to support NFSv4

  - Improve SMB2 integration

  - Fix Blu-ray files using Unicode names on Windows

  - Disable mcast lookups on Android for RTSP playback

       + Video Output: Rework the D3D11 rendering wait, to fix choppiness on
         display
       + Interfaces:

  - Fix VLC getting stuck on close on X11 (#21875)

  - Improve RTL on preferences on macOS

  - Add mousewheel horizontal axis control

  - Fix crash on exit on macOS

  - Fix sizing of the fullscreen controls on macOS

       + Misc:

  - Improve MIDI fonts search on Linux

  - Update Soundcloud, Youtube, liveleak

  - Fix compilation with GCC11

  - Fix input-slave option for subtitles
       + Updated translations.

     Update to version 3.0.12:

       + Access: Add new RIST access module compliant with simple profile
         (VSF_TR-06-1).
       + Access Output: Add new RIST access output module compliant with simple
         profile (VSF_TR-06-1).
       + Demux: Fixed adaptive&#x27 s handling of resolution settings.
       + Audio output: Fix audio distortion on macOS during start of playback.
       + Video Output: Direct3D11: Fix some potential crashes when using video
         filters.
       + Misc:

  - Several fixes in the web interface, including privacy and security
           improvements

  - Update YouTube and Vocaroo scripts.

       + Updated translations.");

  script_tag(name:"affected", value:"'vlc' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"vlc-lang", rpm:"vlc-lang~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5-debuginfo", rpm:"libvlc5-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9-debuginfo", rpm:"libvlccore9-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer", rpm:"vlc-codec-gstreamer~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer-debuginfo", rpm:"vlc-codec-gstreamer-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-debuginfo", rpm:"vlc-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-debugsource", rpm:"vlc-debugsource~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-devel", rpm:"vlc-devel~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack", rpm:"vlc-jack~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack-debuginfo", rpm:"vlc-jack-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX", rpm:"vlc-noX~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX-debuginfo", rpm:"vlc-noX-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv", rpm:"vlc-opencv~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv-debuginfo", rpm:"vlc-opencv-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt", rpm:"vlc-qt~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt-debuginfo", rpm:"vlc-qt-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau", rpm:"vlc-vdpau~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau-debuginfo", rpm:"vlc-vdpau-debuginfo~3.0.13~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
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