# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705078");
  script_cve_id("CVE-2021-45444");
  script_tag(name:"creation_date", value:"2022-02-17 07:17:10 +0000 (Thu, 17 Feb 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 20:16:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5078)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5078");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5078");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5078");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/zsh");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zsh' package(s) announced via the DSA-5078 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that zsh, a powerful shell and scripting language, did not prevent recursive prompt expansion. This would allow an attacker to execute arbitrary commands into a user's shell, for instance by tricking a vcs_info user into checking out a git branch with a specially crafted name.

For the oldstable distribution (buster), this problem has been fixed in version 5.7.1-1+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 5.8-6+deb11u1.

We recommend that you upgrade your zsh packages.

For the detailed security status of zsh please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'zsh' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"zsh", ver:"5.7.1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-common", ver:"5.7.1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-dev", ver:"5.7.1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-doc", ver:"5.7.1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-static", ver:"5.7.1-1+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"zsh", ver:"5.8-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-common", ver:"5.8-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-dev", ver:"5.8-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-doc", ver:"5.8-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zsh-static", ver:"5.8-6+deb11u1", rls:"DEB11"))) {
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
