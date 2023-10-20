# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53351");
  script_cve_id("CVE-2003-0138");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-269");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-269");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-269");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DSA-269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A cryptographic weakness in version 4 of the Kerberos protocol allows an attacker to use a chosen-plaintext attack to impersonate any principal in a realm. Additional cryptographic weaknesses in the krb4 implementation permit the use of cut-and-paste attacks to fabricate krb4 tickets for unauthorized client principals if triple-DES keys are used to key krb4 services. These attacks can subvert a site's entire Kerberos authentication infrastructure.

This version of the heimdal package changes the default behavior and disallows cross-realm authentication for Kerberos version 4. Because of the fundamental nature of the problem, cross-realm authentication in Kerberos version 4 cannot be made secure and sites should avoid its use. A new option (--kerberos4-cross-realm) is provided to the kdc command to re-enable version 4 cross-realm authentication for those sites that must use this functionality but desire the other security fixes.

For the stable distribution (woody) this problem has been fixed in version 0.4e-7.woody.8.

The old stable distribution (potato) is not affected by this problem, since it isn't compiled against kerberos 4.

For the unstable distribution (sid) this problem has been fixed in version 0.5.2-1.

We recommend that you upgrade your heimdal packages immediately.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-lib", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-5-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcomerr1-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi1-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb7-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt4-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv7-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-17-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroken9-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libss0-heimdal", ver:"0.4e-7.woody.8", rls:"DEB3.0"))) {
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
