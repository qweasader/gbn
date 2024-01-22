# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703478");
  script_cve_id("CVE-2015-7511");
  script_tag(name:"creation_date", value:"2016-02-14 23:00:00 +0000 (Sun, 14 Feb 2016)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3478-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3478-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3478");
  script_xref(name:"URL", value:"https://www.cs.tau.ac.IL/~tromer/ecdh/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgcrypt11' package(s) announced via the DSA-3478-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Genkin, Lev Pachmanov, Itamar Pipman and Eran Tromer discovered that the ECDH secret decryption keys in applications using the libgcrypt11 library could be leaked via a side-channel attack.

See [link moved to references] for details.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.5.0-5+deb7u4.

We recommend that you upgrade your libgcrypt11 packages.");

  script_tag(name:"affected", value:"'libgcrypt11' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11", ver:"1.5.0-5+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11-dbg", ver:"1.5.0-5+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11-dev", ver:"1.5.0-5+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11-doc", ver:"1.5.0-5+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11-udeb", ver:"1.5.0-5+deb7u4", rls:"DEB7"))) {
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
