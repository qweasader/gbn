# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56213");
  script_cve_id("CVE-2005-3973", "CVE-2005-3974", "CVE-2005-3975");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-958)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-958");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-958");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-958");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal' package(s) announced via the DSA-958 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in drupal, a fully-featured content management/discussion engine. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2005-3973

Several cross-site scripting vulnerabilities allow remote attackers to inject arbitrary web script or HTML.

CVE-2005-3974

When running on PHP5, Drupal does not correctly enforce user privileges, which allows remote attackers to bypass the 'access user profiles' permission.

CVE-2005-3975

An interpretation conflict allows remote authenticated users to inject arbitrary web script or HTML via HTML in a file with a GIF or JPEG file extension.

The old stable distribution (woody) does not contain drupal packages.

For the stable distribution (sarge) these problems have been fixed in version 4.5.3-5.

For the unstable distribution (sid) these problems have been fixed in version 4.5.6-1.

We recommend that you upgrade your drupal package.");

  script_tag(name:"affected", value:"'drupal' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"drupal", ver:"4.5.3-5", rls:"DEB3.1"))) {
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
