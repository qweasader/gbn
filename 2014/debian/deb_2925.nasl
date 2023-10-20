# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702925");
  script_cve_id("CVE-2014-3121");
  script_tag(name:"creation_date", value:"2014-05-07 22:00:00 +0000 (Wed, 07 May 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2925)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2925");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2925");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2925");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rxvt-unicode' package(s) announced via the DSA-2925 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Phillip Hallam-Baker discovered that window property values could be queried in rxvt-unicode, resulting in the potential execution of arbitrary commands.

For the oldstable distribution (squeeze), this problem has been fixed in version 9.07-2+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in version 9.15-2+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 9.20-1.

For the unstable distribution (sid), this problem has been fixed in version 9.20-1.

We recommend that you upgrade your rxvt-unicode packages.");

  script_tag(name:"affected", value:"'rxvt-unicode' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode", ver:"9.07-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode-lite", ver:"9.07-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode-ml", ver:"9.07-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode", ver:"9.15-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode-256color", ver:"9.15-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode-lite", ver:"9.15-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rxvt-unicode-ml", ver:"9.15-2+deb7u1", rls:"DEB7"))) {
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
