# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53690");
  script_cve_id("CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-549-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-549-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-549");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gtk+2.0' package(s) announced via the DSA-549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered several problems in gdk-pixbuf, the GdkPixBuf library used in Gtk. It is possible for an attacker to execute arbitrary code on the victims machine. Gdk-pixbuf for Gtk+1.2 is an external package. For Gtk+2.0 it's part of the main gtk package.

The Common Vulnerabilities and Exposures Project identifies the following vulnerabilities:

CAN-2004-0782

Heap-based overflow in pixbuf_create_from_xpm.

CAN-2004-0783

Stack-based overflow in xpm_extract_color.

CAN-2004-0788

Integer overflow in the ico loader.

For the stable distribution (woody) these problems have been fixed in version 2.0.2-5woody2.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your Gtk packages.");

  script_tag(name:"affected", value:"'gtk+2.0' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"gtk2.0-examples", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgtk-common", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgtk2.0-0", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgtk2.0-common", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgtk2.0-dbg", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgtk2.0-dev", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgtk2.0-doc", ver:"2.0.2-5woody2", rls:"DEB3.0"))) {
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
