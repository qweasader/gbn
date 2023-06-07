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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0329");
  script_cve_id("CVE-2015-5949");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0329)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0329");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0329.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16631");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2015-009.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2015/msg00241.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the MGASA-2015-0329 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Loren Maggiore of Trail of Bits discovered that the 3GP parser of VLC, a
multimedia player and streamer, could dereference an arbitrary pointer
due to insufficient restrictions on a writable buffer. This could allow
remote attackers to execute arbitrary code via crafted 3GP files
(CVE-2015-5949).");

  script_tag(name:"affected", value:"'vlc' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore7", rpm:"lib64vlccore7~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore7", rpm:"lib64vlccore7~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore7", rpm:"libvlccore7~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore7", rpm:"libvlccore7~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-bonjour", rpm:"vlc-plugin-bonjour~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-bonjour", rpm:"vlc-plugin-bonjour~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~2.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~2.1.6~1.1.mga4.tainted", rls:"MAGEIA4"))) {
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
