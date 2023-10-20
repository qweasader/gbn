# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892131");
  script_cve_id("CVE-2014-6262");
  script_tag(name:"creation_date", value:"2020-03-02 04:00:06 +0000 (Mon, 02 Mar 2020)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 14:15:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Debian: Security Advisory (DLA-2131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2131");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2131-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rrdtool' package(s) announced via the DLA-2131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a regression in a previous fix, which resulted in the following error:

ERROR: cannot compile regular expression: Error while compiling regular expression ^(?:[^%]+<pipe>%%)*%[+- 0#]?[0-9]*([.][0-9]+)?l[eEfF](?:[^%]+<pipe>%%) *%s(?:[^%]+<pipe>%%)*$ at char 18: range out of order in character class (^(?:[ ^%]+<pipe>%%)*%[+- 0#]?[0-9]*([.][0-9]+)?l[eEfF](?:[^%]+<pipe>%%)*%s(?:[^%]+<pipe>%%)*$)

For Debian 8 Jessie, this problem has been fixed in version 1.4.8-1.2+deb8u2.

We recommend that you upgrade your rrdtool packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'rrdtool' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblua5.1-rrd-dev", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblua5.1-rrd0", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrd-dev", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrd-ruby", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrd-ruby1.8", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrd-ruby1.9.1", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrd4", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrdp-perl", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librrds-perl", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rrdtool", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rrdcached", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rrdtool", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rrdtool-dbg", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rrdtool-tcl", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rrd", ver:"1.4.8-1.2+deb8u1", rls:"DEB8"))) {
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
