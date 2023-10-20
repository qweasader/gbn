# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0168");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2016-0168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0168");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0168.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18351");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=vlc/vlc-2.2.git;a=blob;f=NEWS;h=c8bc5dd77b4fb1f6094f9ec447def98055800ede;hb=HEAD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the MGASA-2016-0168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated vlc packages fix security vulnerabilities:

The vlc package has been updated to version 2.2.3, which fixes several
bugs and possible security issues. See the NEWS file for details.");

  script_tag(name:"affected", value:"'vlc' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore8", rpm:"lib64vlccore8~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore8", rpm:"lib64vlccore8~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore8", rpm:"libvlccore8~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore8", rpm:"libvlccore8~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-bonjour", rpm:"vlc-plugin-bonjour~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-bonjour", rpm:"vlc-plugin-bonjour~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-chromaprint", rpm:"vlc-plugin-chromaprint~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-chromaprint", rpm:"vlc-plugin-chromaprint~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-vdpau", rpm:"vlc-plugin-vdpau~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-vdpau", rpm:"vlc-plugin-vdpau~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~2.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~2.2.3~1.mga5.tainted", rls:"MAGEIA5"))) {
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
