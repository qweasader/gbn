# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892129");
  script_cve_id("CVE-2017-11509");
  script_tag(name:"creation_date", value:"2020-03-01 04:00:15 +0000 (Sun, 01 Mar 2020)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 22:14:00 +0000 (Tue, 23 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-2129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2129");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2129");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firebird2.5' package(s) announced via the DLA-2129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issues has been found in firebird2.5, an RDBMS based on InterBase 6.0. As UDFs can be used for a remote authenticated code execution (as user firebird), UDFs have been disabled in the default configuration which will be used for new installations (there is no change for existing configurations, which must be done manually).

For Debian 8 Jessie, this problem has been fixed in version 2.5.3.26778.ds4-5+deb8u2.

We recommend that you upgrade your firebird2.5 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firebird2.5' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firebird-dev", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic-common", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic-dbg", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-common", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-common-doc", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-doc", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-examples", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-server-common", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-super", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-super-dbg", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-superclassic", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbclient2", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbclient2-dbg", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbembed2.5", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libib-util", ver:"2.5.3.26778.ds4-5+deb8u2", rls:"DEB8"))) {
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
