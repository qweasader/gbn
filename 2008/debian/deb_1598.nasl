# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61174");
  script_cve_id("CVE-2008-0553");
  script_tag(name:"creation_date", value:"2008-06-27 22:42:46 +0000 (Fri, 27 Jun 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1598-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1598-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1598");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtk-img' package(s) announced via the DSA-1598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a buffer overflow in the GIF image parsing code of Tk, a cross-platform graphical toolkit, could lead to denial of service and potentially the execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in version 1:1.3-15etch2.

For the unstable distribution (sid), this problem has been fixed in version 1:1.3-release-7.

We recommend that you upgrade your libtk-img package.");

  script_tag(name:"affected", value:"'libtk-img' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtk-img", ver:"1:1.3-15etch2", rls:"DEB4"))) {
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
