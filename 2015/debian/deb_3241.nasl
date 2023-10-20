# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703241");
  script_cve_id("CVE-2015-3337");
  script_tag(name:"creation_date", value:"2015-04-28 22:00:00 +0000 (Tue, 28 Apr 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3241");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3241");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3241");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'elasticsearch' package(s) announced via the DSA-3241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"John Heasman discovered that the site plugin handling of the Elasticsearch search engine was susceptible to directory traversal.

For the stable distribution (jessie), this problem has been fixed in version 1.0.3+dfsg-5+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your elasticsearch packages.");

  script_tag(name:"affected", value:"'elasticsearch' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"elasticsearch", ver:"1.0.3+dfsg-5+deb8u1", rls:"DEB8"))) {
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
