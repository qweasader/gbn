# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63298");
  script_cve_id("CVE-2009-0282");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1712)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1712");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1712");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1712");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rt2400' package(s) announced via the DSA-1712 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an integer overflow in the 'Probe Request' packet parser of the Ralinktech wireless drivers might lead to remote denial of service or the execution of arbitrary code.

Please note that you need to rebuild your driver from the source package in order to set this update into effect. Detailed instructions can be found in /usr/share/doc/rt2400-source/README.Debian

For the stable distribution (etch), this problem has been fixed in version 1.2.2+cvs20060620-4+etch1.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), this problem has been fixed in version 1.2.2+cvs20080623-3.

We recommend that you upgrade your rt2400 package.");

  script_tag(name:"affected", value:"'rt2400' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"rt2400", ver:"1.2.2+cvs20060620-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt2400-source", ver:"1.2.2+cvs20060620-4+etch1", rls:"DEB4"))) {
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
