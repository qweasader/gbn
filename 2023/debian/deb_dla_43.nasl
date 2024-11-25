# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.43");
  script_cve_id("CVE-2014-0475", "CVE-2014-5119");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-43-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-43-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-43-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eglibc' package(s) announced via the DLA-43-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2014-0475

Stephane Chazelas discovered that the GNU C library, glibc, processed '..' path segments in locale-related environment variables, possibly allowing attackers to circumvent intended restrictions, such as ForceCommand in OpenSSH, assuming that they can supply crafted locale settings.

CVE-2014-5119

Tavis Ormandy discovered a heap-based buffer overflow in the transliteration module loading code in eglibc, Debian's version of the GNU C Library. As a result, an attacker who can supply a crafted destination character set argument to iconv-related character conversation functions could achieve arbitrary code execution.

This update removes support of loadable gconv transliteration modules. Besides the security vulnerability, the module loading code had functionality defects which prevented it from working for the intended purpose.

For Debian 6 Squeeze, these issues have been fixed in eglibc version 2.11.3-4+deb6u1");

  script_tag(name:"affected", value:"'eglibc' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"eglibc-source", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glibc-doc", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i386", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i686", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-pic", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-prof", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-udeb", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-xen", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dns-udeb", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-files-udeb", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales-all", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nscd", ver:"2.11.3-4+deb6u1", rls:"DEB6"))) {
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
