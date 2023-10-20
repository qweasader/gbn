# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71234");
  script_cve_id("CVE-2012-1502");
  script_tag(name:"creation_date", value:"2012-04-30 11:54:11 +0000 (Mon, 30 Apr 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2430");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2430");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2430");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-pam' package(s) announced via the DSA-2430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Markus Vervier discovered a double free in the Python interface to the PAM library, which could lead to denial of service.

For the stable distribution (squeeze), this problem has been fixed in version 0.4.2-12.2+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 0.4.2-13.

We recommend that you upgrade your python-pam packages.");

  script_tag(name:"affected", value:"'python-pam' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pam", ver:"0.4.2-12.2+squeeze1", rls:"DEB6"))) {
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
