# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63795");
  script_cve_id("CVE-2009-1250", "CVE-2009-1251");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1768-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1768-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1768-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1768");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-1768-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the client part of OpenAFS, a distributed file system.

CVE-2009-1251

An attacker with control of a file server or the ability to forge RX packets may be able to execute arbitrary code in kernel mode on an OpenAFS client, due to a vulnerability in XDR array decoding.

CVE-2009-1250

An attacker with control of a file server or the ability to forge RX packets may crash OpenAFS clients because of wrongly handled error return codes in the kernel module.

Note that in order to apply this security update, you must rebuild the OpenAFS kernel module. Be sure to also upgrade openafs-modules-source, build a new kernel module for your system following the instructions in /usr/share/doc/openafs-client/README.modules.gz, and then either stop and restart openafs-client or reboot the system to reload the kernel module.

For the old stable distribution (etch), these problems have been fixed in version 1.4.2-6etch2.

For the stable distribution (lenny), these problems have been fixed in version 1.4.7.dfsg1-6+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 1.4.10+dfsg1-1.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.2-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.7.dfsg1-6+lenny1", rls:"DEB5"))) {
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
