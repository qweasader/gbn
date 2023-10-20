# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705029");
  script_cve_id("CVE-2021-33054");
  script_tag(name:"creation_date", value:"2021-12-23 10:04:55 +0000 (Thu, 23 Dec 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 22:15:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-5029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5029");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5029");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5029");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sogo");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sogo' package(s) announced via the DSA-5029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that missing SAML signature validation in the SOGo groupware could result in impersonation attacks.

For the oldstable distribution (buster), this problem has been fixed in version 4.0.7-1+deb10u2.

For the stable distribution (bullseye), this problem has been fixed in version 5.0.1-4+deb11u1.

We recommend that you upgrade your sogo packages.

For the detailed security status of sogo please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'sogo' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sogo", ver:"4.0.7-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sogo-common", ver:"4.0.7-1+deb10u2", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sogo", ver:"5.0.1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sogo-common", ver:"5.0.1-4+deb11u1", rls:"DEB11"))) {
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
