# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703129");
  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_tag(name:"creation_date", value:"2015-01-14 23:00:00 +0000 (Wed, 14 Jan 2015)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3129-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3129-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3129");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rpm' package(s) announced via the DSA-3129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in the RPM package manager.

CVE-2013-6435

Florian Weimer discovered a race condition in package signature validation.

CVE-2014-8118

Florian Weimer discovered an integer overflow in parsing CPIO headers which might result in the execution of arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 4.10.0-5+deb7u2.

For the upcoming stable distribution (jessie), these problems have been fixed in version 4.11.3-1.1.

For the unstable distribution (sid), these problems have been fixed in version 4.11.3-1.1.

We recommend that you upgrade your rpm packages.");

  script_tag(name:"affected", value:"'rpm' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"librpm-dbg", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpm-dev", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpm3", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpmbuild3", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpmio3", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpmsign1", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rpm", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm-common", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm-i18n", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm2cpio", ver:"4.10.0-5+deb7u2", rls:"DEB7"))) {
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
