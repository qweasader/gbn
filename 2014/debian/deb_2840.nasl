# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702840");
  script_cve_id("CVE-2013-2139");
  script_tag(name:"creation_date", value:"2014-01-09 23:00:00 +0000 (Thu, 09 Jan 2014)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2840-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2840-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2840");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'srtp' package(s) announced via the DSA-2840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fernando Russ from Groundworks Technologies reported a buffer overflow flaw in srtp, Cisco's reference implementation of the Secure Real-time Transport Protocol (SRTP), in how the crypto_policy_set_from_profile_for_rtp() function applies cryptographic profiles to an srtp_policy. A remote attacker could exploit this vulnerability to crash an application linked against libsrtp, resulting in a denial of service.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.4.4~dfsg-6+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in version 1.4.4+20100615~dfsg-2+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 1.4.5~20130609~dfsg-1.

For the unstable distribution (sid), this problem has been fixed in version 1.4.5~20130609~dfsg-1.

We recommend that you upgrade your srtp packages.");

  script_tag(name:"affected", value:"'srtp' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0", ver:"1.4.4~dfsg-6+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0-dev", ver:"1.4.4~dfsg-6+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-docs", ver:"1.4.4~dfsg-6+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-utils", ver:"1.4.4~dfsg-6+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0", ver:"1.4.4+20100615~dfsg-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0-dev", ver:"1.4.4+20100615~dfsg-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-docs", ver:"1.4.4+20100615~dfsg-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-utils", ver:"1.4.4+20100615~dfsg-2+deb7u1", rls:"DEB7"))) {
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
