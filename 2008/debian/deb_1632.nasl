# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61589");
  script_cve_id("CVE-2008-2327");
  script_tag(name:"creation_date", value:"2008-09-17 02:23:15 +0000 (Wed, 17 Sep 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1632)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1632");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1632");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1632");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-1632 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Drew Yao discovered that libTIFF, a library for handling the Tagged Image File Format, is vulnerable to a programming error allowing malformed tiff files to lead to a crash or execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in version 3.8.2-7+etch1.

For the testing distribution (lenny), this problem has been fixed in version 3.8.2-10+lenny1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your tiff package.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.8.2-7+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.8.2-7+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-7+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.8.2-7+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.8.2-7+etch1", rls:"DEB4"))) {
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
