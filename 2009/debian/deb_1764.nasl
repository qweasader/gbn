# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63791");
  script_cve_id("CVE-2009-1253", "CVE-2009-1254");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1764)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1764");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1764");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1764");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tunapie' package(s) announced via the DSA-1764 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Tunapie, a GUI frontend to video and radio streams. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1253

Kees Cook discovered that insecure handling of temporary files may lead to local denial of service through symlink attacks.

CVE-2009-1254

Mike Coleman discovered that insufficient escaping of stream URLs may lead to the execution of arbitrary commands if a user is tricked into opening a malformed stream URL.

For the old stable distribution (etch), these problems have been fixed in version 1.3.1-1+etch2. Due to a technical problem, this update cannot be released synchronously with the stable (lenny) version, but will appear soon.

For the stable distribution (lenny), these problems have been fixed in version 2.1.8-2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your tunapie package.");

  script_tag(name:"affected", value:"'tunapie' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"tunapie", ver:"2.1.8-2", rls:"DEB5"))) {
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
