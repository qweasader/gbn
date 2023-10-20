# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702988");
  script_cve_id("CVE-2014-4909");
  script_tag(name:"creation_date", value:"2014-07-23 22:00:00 +0000 (Wed, 23 Jul 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2988)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2988");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2988");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2988");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'transmission' package(s) announced via the DSA-2988 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Hawkes discovered that incorrect handling of peer messages in the Transmission bittorrent client could result in denial of service or the execution of arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 2.52-3+nmu2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your transmission packages.");

  script_tag(name:"affected", value:"'transmission' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"transmission", ver:"2.52-3+nmu2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-cli", ver:"2.52-3+nmu2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-common", ver:"2.52-3+nmu2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-daemon", ver:"2.52-3+nmu2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-dbg", ver:"2.52-3+nmu2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-gtk", ver:"2.52-3+nmu2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-qt", ver:"2.52-3+nmu2", rls:"DEB7"))) {
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
