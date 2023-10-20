# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704803");
  script_cve_id("CVE-2020-14360", "CVE-2020-25712");
  script_tag(name:"creation_date", value:"2020-12-08 10:02:45 +0000 (Tue, 08 Dec 2020)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 18:29:00 +0000 (Tue, 26 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4803)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4803");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4803");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4803");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xorg-server");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xorg-server' package(s) announced via the DSA-4803 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan-Niklas Sohn discovered that the XKB extension of the Xorg X server performed incomplete input validation, which could result in privilege escalation.

For the stable distribution (buster), these problems have been fixed in version 2:1.20.4-1+deb10u2.

We recommend that you upgrade your xorg-server packages.

For the detailed security status of xorg-server please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xdmx", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xdmx-tools", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xnest", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xorg-server-source", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-common", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xephyr", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core-udeb", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-legacy", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvfb", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.20.4-1+deb10u2", rls:"DEB10"))) {
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
