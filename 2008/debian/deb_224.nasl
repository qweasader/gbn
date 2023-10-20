# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53720");
  script_cve_id("CVE-2002-1158", "CVE-2002-1159");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-224)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-224");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-224");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-224");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'canna' package(s) announced via the DSA-224 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in canna, a Japanese input system. The Common Vulnerabilities and Exposures (CVE) project identified the following vulnerabilities:

CAN-2002-1158 (BugTraq Id 6351): 'hsj' of Shadow Penguin Security discovered a heap overflow vulnerability in the irw_through function in canna server.

CAN-2002-1159 (BugTraq Id 6354): Shinra Aida of the Canna project discovered that canna does not properly validate requests, which allows remote attackers to cause a denial of service or information leak.

For the current stable distribution (woody) these problems have been fixed in version 3.5b2-46.2.

For the old stable distribution (potato) these problems have been fixed in version 3.5b2-25.2.

For the unstable distribution (sid) these problems have been fixed in version 3.6p1-1.

We recommend that you upgrade your canna packages.");

  script_tag(name:"affected", value:"'canna' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"canna", ver:"3.5b2-46.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"canna-utils", ver:"3.5b2-46.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcanna1g", ver:"3.5b2-46.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcanna1g-dev", ver:"3.5b2-46.2", rls:"DEB3.0"))) {
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
