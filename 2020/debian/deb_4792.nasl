# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704792");
  script_cve_id("CVE-2020-25709", "CVE-2020-25710");
  script_tag(name:"creation_date", value:"2020-11-18 04:00:11 +0000 (Wed, 18 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-01 21:32:47 +0000 (Tue, 01 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-4792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4792-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4792-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4792");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openldap");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openldap' package(s) announced via the DSA-4792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities in the certificate list syntax verification and in the handling of CSN normalization were discovered in OpenLDAP, a free implementation of the Lightweight Directory Access Protocol. An unauthenticated remote attacker can take advantage of these flaws to cause a denial of service (slapd daemon crash) via specially crafted packets.

For the stable distribution (buster), these problems have been fixed in version 2.4.47+dfsg-3+deb10u4.

We recommend that you upgrade your openldap packages.

For the detailed security status of openldap please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openldap' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-common", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-contrib", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-smbk5pwd", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapi-dev", ver:"2.4.47+dfsg-3+deb10u4", rls:"DEB10"))) {
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
