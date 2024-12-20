# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.222");
  script_cve_id("CVE-2012-5783", "CVE-2012-6153", "CVE-2014-3577");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DLA-222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-222-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-222-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'commons-httpclient' package(s) announced via the DLA-222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2012-5783

and CVE-2012-6153 Apache Commons HttpClient 3.1 did not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate. Thanks to Alberto Fernandez Martinez for the patch.

CVE-2014-3577

It was found that the fix for CVE-2012-6153 was incomplete: the code added to check that the server hostname matches the domain name in a subject's Common Name (CN) field in X.509 certificates was flawed. A man-in-the-middle attacker could use this flaw to spoof an SSL server using a specially crafted X.509 certificate. The fix for CVE-2012-6153 was intended to address the incomplete patch for CVE-2012-5783. The issue is now completely resolved by applying this patch and the one for the previous CVEs

This upload was prepared by Markus Koschany.");

  script_tag(name:"affected", value:"'commons-httpclient' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-9+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcommons-httpclient-java-doc", ver:"3.1-9+deb6u1", rls:"DEB6"))) {
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
