# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704215");
  script_cve_id("CVE-2017-5662", "CVE-2018-8013");
  script_tag(name:"creation_date", value:"2018-06-01 22:00:00 +0000 (Fri, 01 Jun 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4215-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4215-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4215-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4215");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/batik");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'batik' package(s) announced via the DSA-4215-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Man Yue Mo, Lars Krapf and Pierre Ernst discovered that Batik, a toolkit for processing SVG images, did not properly validate its input. This would allow an attacker to cause a denial-of-service, mount cross-site scripting attacks, or access restricted files on the server.

For the oldstable distribution (jessie), these problems have been fixed in version 1.7+dfsg-5+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 1.8-4+deb9u1.

We recommend that you upgrade your batik packages.

For the detailed security status of batik please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'batik' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libbatik-java", ver:"1.7+dfsg-5+deb8u1", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libbatik-java", ver:"1.8-4+deb9u1", rls:"DEB9"))) {
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
