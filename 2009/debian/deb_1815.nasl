# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64249");
  script_cve_id("CVE-2009-1760");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1815-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1815-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1815-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1815");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtorrent-rasterbar' package(s) announced via the DSA-1815-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Rasterbar Bittorrent library performed insufficient validation of path names specified in torrent files, which could lead to denial of service by overwriting files.

The old stable distribution (etch) doesn't include libtorrent-rasterbar.

For the stable distribution (lenny), this problem has been fixed in version 0.13.1-2+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 0.14.4-1.

We recommend that you upgrade your libtorrent-rasterbar package.");

  script_tag(name:"affected", value:"'libtorrent-rasterbar' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtorrent-rasterbar-dbg", ver:"0.13.1-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtorrent-rasterbar-dev", ver:"0.13.1-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtorrent-rasterbar-doc", ver:"0.13.1-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtorrent-rasterbar0", ver:"0.13.1-2+lenny1", rls:"DEB5"))) {
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
