# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0203");
  script_cve_id("CVE-2019-19721", "CVE-2020-6071", "CVE-2020-6072", "CVE-2020-6073", "CVE-2020-6077", "CVE-2020-6078", "CVE-2020-6079", "CVE-2020-6080");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-15 00:15:00 +0000 (Fri, 15 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0203");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0203.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26467");
  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc309.html");
  script_xref(name:"URL", value:"https://www.videolan.org/developers/vlc-branch/NEWS");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4671");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the MGASA-2020-0203 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the microdns plugin of the
VLC media player, which could result in denial of service or potentially
the execution of arbitrary code via malicious mDNS packets (CVE-2020-6071,
CVE-2020-6072, CVE-2020-6073, CVE-2020-6077, CVE-2020-6078, CVE-2020-6079,
CVE-2020-6080).

VLC has been updated to 3.0.10 to fix these and other issues.");

  script_tag(name:"affected", value:"'vlc' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore9", rpm:"lib64vlccore9~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore9", rpm:"lib64vlccore9~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-chromaprint", rpm:"vlc-plugin-chromaprint~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-chromaprint", rpm:"vlc-plugin-chromaprint~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fdkaac", rpm:"vlc-plugin-fdkaac~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-samba", rpm:"vlc-plugin-samba~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-samba", rpm:"vlc-plugin-samba~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sndio", rpm:"vlc-plugin-sndio~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sndio", rpm:"vlc-plugin-sndio~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-vdpau", rpm:"vlc-plugin-vdpau~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-vdpau", rpm:"vlc-plugin-vdpau~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~3.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~3.0.10~1.mga7.tainted", rls:"MAGEIA7"))) {
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
