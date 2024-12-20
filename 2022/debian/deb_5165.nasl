# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705165");
  script_tag(name:"creation_date", value:"2022-06-21 01:00:23 +0000 (Tue, 21 Jun 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5165-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5165-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5165");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/vlc");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-5165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the VLC media player, which could result in the execution of arbitrary code or denial of service if a malformed file is opened.

For the oldstable distribution (buster), this problem has been fixed in version 3.0.17.4-0+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 3.0.17.4-0+deb11u1.

We recommend that you upgrade your vlc packages.

For the detailed security status of vlc please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libvlc-bin", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlc-dev", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlc5", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlccore-dev", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlccore9", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-bin", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-data", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-l10n", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-base", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-fluidsynth", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-notify", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-qt", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-samba", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-skins2", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-svg", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-output", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-splitter", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-visualization", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-zvbi", ver:"3.0.17.4-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libvlc-bin", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlc-dev", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlc5", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlccore-dev", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlccore9", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-bin", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-data", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-l10n", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-base", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-fluidsynth", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-notify", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-qt", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-samba", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-skins2", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-svg", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-output", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-splitter", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-visualization", ver:"3.0.17.4-0+deb11u1", rls:"DEB11"))) {
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
