# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54189");
  script_cve_id("CVE-2005-1858");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-744)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-744");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-744");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-744");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fuse' package(s) announced via the DSA-744 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sven Tantau discovered a security problem in fuse, a filesystem in userspace, that can be exploited by malicious, local users to disclose potentially sensitive information.

The old stable distribution (woody) does not contain the fuse package.

For the stable distribution (sarge) this problem has been fixed in version 2.2.1-4sarge2.

For the unstable distribution (sid) this problem has been fixed in version 2.3.0-1.

We recommend that you upgrade your fuse package.");

  script_tag(name:"affected", value:"'fuse' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fuse-source", ver:"2.2.1-4sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-utils", ver:"2.2.1-4sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse-dev", ver:"2.2.1-4sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse2", ver:"2.2.1-4sarge2", rls:"DEB3.1"))) {
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
