# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891695");
  script_cve_id("CVE-2017-15370", "CVE-2017-15372", "CVE-2017-15642", "CVE-2017-18189", "CVE-2019-1010004");
  script_tag(name:"creation_date", value:"2019-02-27 23:00:00 +0000 (Wed, 27 Feb 2019)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 15:16:00 +0000 (Thu, 24 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-1695)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1695");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1695");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sox' package(s) announced via the DLA-1695 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in SoX (Sound eXchange), a sound processing program:

CVE-2017-15370

The ImaAdpcmReadBlock function (src/wav.c) is affected by a heap buffer overflow. This vulnerability might be leveraged by remote attackers using a crafted WAV file to cause denial of service (application crash).

CVE-2017-15372

The lsx_ms_adpcm_block_expand_i function (adpcm.c) is affected by a stack based buffer overflow. This vulnerability might be leveraged by remote attackers using a crafted audio file to cause denial of service (application crash).

CVE-2017-15642

The lsx_aiffstartread function (aiff.c) is affected by a use-after-free vulnerability. This flaw might be leveraged by remote attackers using a crafted AIFF file to cause denial of service (application crash).

CVE-2017-18189

The startread function (xa.c) is affected by a null pointer dereference vulnerability. This flaw might be leveraged by remote attackers using a crafted Maxis XA audio file to cause denial of service (application crash).

For Debian 8 Jessie, these problems have been fixed in version 14.4.1-5+deb8u2.

We recommend that you upgrade your sox packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sox' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsox-dev", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-all", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-alsa", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-ao", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-base", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-mp3", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-oss", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-pulse", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox2", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.1-5+deb8u2", rls:"DEB8"))) {
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
