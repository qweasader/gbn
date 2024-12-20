# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703735");
  script_cve_id("CVE-2016-9957", "CVE-2016-9958", "CVE-2016-9959", "CVE-2016-9960", "CVE-2016-9961");
  script_tag(name:"creation_date", value:"2016-12-14 23:00:00 +0000 (Wed, 14 Dec 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-15 19:50:42 +0000 (Thu, 15 Jun 2017)");

  script_name("Debian: Security Advisory (DSA-3735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3735-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3735-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3735");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.de/2016/12/redux-compromising-linux-using-snes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'game-music-emu' package(s) announced via the DSA-3735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered that incorrect emulation of the SPC700 audio co-processor of the Super Nintendo Entertainment System allows the execution of arbitrary code if a malformed SPC music file is opened. Further information can be found at [link moved to references]

For the stable distribution (jessie), this problem has been fixed in version 0.5.5-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 0.6.0-4.

We recommend that you upgrade your game-music-emu packages.");

  script_tag(name:"affected", value:"'game-music-emu' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libgme-dev", ver:"0.5.5-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgme0", ver:"0.5.5-2+deb8u1", rls:"DEB8"))) {
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
