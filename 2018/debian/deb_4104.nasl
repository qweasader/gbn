# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704104");
  script_cve_id("CVE-2017-17969");
  script_tag(name:"creation_date", value:"2018-02-03 23:00:00 +0000 (Sat, 03 Feb 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 20:29:00 +0000 (Thu, 21 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-4104-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4104-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4104-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4104");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/p7zip");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'p7zip' package(s) announced via the DSA-4104-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'landave' discovered a heap-based buffer overflow vulnerability in the NCompress::NShrink::CDecoder::CodeReal method in p7zip, a 7zr file archiver with high compression ratio. A remote attacker can take advantage of this flaw to cause a denial-of-service or, potentially the execution of arbitrary code with the privileges of the user running p7zip, if a specially crafted shrunk ZIP archive is processed.

For the oldstable distribution (jessie), this problem has been fixed in version 9.20.1~dfsg.1-4.1+deb8u3.

For the stable distribution (stretch), this problem has been fixed in version 16.02+dfsg-3+deb9u1.

We recommend that you upgrade your p7zip packages.

For the detailed security status of p7zip please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'p7zip' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"p7zip", ver:"9.20.1~dfsg.1-4.1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"p7zip-full", ver:"9.20.1~dfsg.1-4.1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"p7zip", ver:"16.02+dfsg-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"p7zip-full", ver:"16.02+dfsg-3+deb9u1", rls:"DEB9"))) {
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
