# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703078");
  script_cve_id("CVE-2014-9087");
  script_tag(name:"creation_date", value:"2014-11-26 23:00:00 +0000 (Wed, 26 Nov 2014)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3078)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3078");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3078");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3078");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libksba' package(s) announced via the DSA-3078 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer underflow flaw, leading to a heap-based buffer overflow, was found in the ksba_oid_to_str() function of libksba, an X.509 and CMS (PKCS#7) library. By using special crafted S/MIME messages or ECC based OpenPGP data, it is possible to create a buffer overflow, which could cause an application using libksba to crash (denial of service), or potentially, execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 1.2.0-2+deb7u1.

For the upcoming stable distribution (jessie), this problem has been fixed in version 1.3.2-1.

For the unstable distribution (sid), this problem has been fixed in version 1.3.2-1.

We recommend that you upgrade your libksba packages.");

  script_tag(name:"affected", value:"'libksba' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libksba-dev", ver:"1.2.0-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libksba8", ver:"1.2.0-2+deb7u1", rls:"DEB7"))) {
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
