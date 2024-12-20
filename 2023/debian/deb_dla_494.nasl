# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.494");
  script_cve_id("CVE-2016-1234", "CVE-2016-3075", "CVE-2016-3706");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-10 17:46:36 +0000 (Fri, 10 Jun 2016)");

  script_name("Debian: Security Advisory (DLA-494-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-494-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-494-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eglibc' package(s) announced via the DLA-494-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in the Debian GNU C Library, eglibc:

CVE-2016-1234

Alexander Cherepanov discovered that the glibc's glob implementation suffered from a stack-based buffer overflow when it was called with the GLOB_ALTDIRFUNC flag and encountered a long file name.

CVE-2016-3075

The getnetbyname implementation in nss_dns was susceptible to a stack overflow and a crash if it was invoked on a very long name.

CVE-2016-3706

Michael Petlan reported that getaddrinfo copied large amounts of address data to the stack, possibly leading to a stack overflow. This complements the fix for CVE-2013-4458.

For Debian 7 Wheezy, these problems have been fixed in version 2.13-38+deb7u11.

We recommend you to upgrade your eglibc packages.

Further information about Debian LTS security advisories, how to apply these updates to your system, and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'eglibc' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"eglibc-source", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glibc-doc", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i386", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i686", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-pic", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-prof", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-udeb", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-xen", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dns-udeb", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-files-udeb", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales-all", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multiarch-support", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nscd", ver:"2.13-38+deb7u11", rls:"DEB7"))) {
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
