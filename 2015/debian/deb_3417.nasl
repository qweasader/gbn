# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703417");
  script_cve_id("CVE-2015-7940");
  script_tag(name:"creation_date", value:"2015-12-13 23:00:00 +0000 (Sun, 13 Dec 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3417)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3417");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3417");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3417");
  script_xref(name:"URL", value:"http://web-in-security.blogspot.ca/2015/09/practical-invalid-curve-attacks.html");
  script_xref(name:"URL", value:"http://euklid.org/pdf/ECC_Invalid_Curve.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bouncycastle' package(s) announced via the DSA-3417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tibor Jager, Jorg Schwenk, and Juraj Somorovsky, from Horst Gortz Institute for IT Security, published a paper in ESORICS 2015 where they describe an invalid curve attack in Bouncy Castle Crypto, a Java library for cryptography. An attacker is able to recover private Elliptic Curve keys from different applications, for example, TLS servers.

More information: [link moved to references] Practical Invalid Curve Attacks on TLS-ECDH: [link moved to references]

For the oldstable distribution (wheezy), this problem has been fixed in version 1.44+dfsg-3.1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 1.49+dfsg-3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1.51-2.

We recommend that you upgrade your bouncycastle packages.");

  script_tag(name:"affected", value:"'bouncycastle' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java-doc", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java-gcj", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java-doc", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java-gcj", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java-doc", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java-gcj", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbctsp-java", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbctsp-java-doc", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbctsp-java-gcj", ver:"1.44+dfsg-3.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java-doc", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java-doc", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpkix-java", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpkix-java-doc", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java-doc", ver:"1.49+dfsg-3+deb8u1", rls:"DEB8"))) {
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
