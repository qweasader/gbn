# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60367");
  script_cve_id("CVE-2008-0553");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1490)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1490");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1490");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1490");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tk8.3' package(s) announced via the DSA-1490 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a buffer overflow in the GIF image parsing code of Tk, a cross-platform graphical toolkit, could lead to a denial of service and potentially the execution of arbitrary code.

For the old stable distribution (sarge), this problem has been fixed in version 8.3.5-4sarge1.

For the stable distribution (etch), this problem has been fixed in version 8.3.5-6etch2.

We recommend that you upgrade your tk8.3 packages.");

  script_tag(name:"affected", value:"'tk8.3' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"tk8.3", ver:"8.3.5-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tk8.3-dev", ver:"8.3.5-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tk8.3-doc", ver:"8.3.5-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"tk8.3", ver:"8.3.5-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tk8.3-dev", ver:"8.3.5-6etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tk8.3-doc", ver:"8.3.5-6etch2", rls:"DEB4"))) {
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
