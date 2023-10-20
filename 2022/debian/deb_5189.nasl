# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705189");
  script_cve_id("CVE-2022-2469");
  script_tag(name:"creation_date", value:"2022-07-26 01:00:07 +0000 (Tue, 26 Jul 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 22:38:00 +0000 (Wed, 27 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5189");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5189");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5189");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gsasl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gsasl' package(s) announced via the DSA-5189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon Josefsson discovered an out-of-bounds memory read in GNU SASL, an implementation of the Simple Authentication and Security Layer framework, which could result in denial of service.

For the oldstable distribution (buster), this problem has been fixed in version 1.8.0-8+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 1.10.0-4+deb11u1.

We recommend that you upgrade your gsasl packages.

For the detailed security status of gsasl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gsasl' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gsasl", ver:"1.8.0-8+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gsasl-dbg", ver:"1.8.0-8+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgsasl7", ver:"1.8.0-8+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgsasl7-dev", ver:"1.8.0-8+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gsasl", ver:"1.10.0-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gsasl-common", ver:"1.10.0-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gsasl-doc", ver:"1.10.0-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgsasl-dev", ver:"1.10.0-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgsasl7", ver:"1.10.0-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgsasl7-dev", ver:"1.10.0-4+deb11u1", rls:"DEB11"))) {
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
