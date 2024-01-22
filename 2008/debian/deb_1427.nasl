# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60006");
  script_cve_id("CVE-2007-6015");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1427-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1427-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1427");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-1427-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop discovered that Samba, a LanManager-like file and printer server for Unix, is vulnerable to a buffer overflow in the nmbd code which handles GETDC mailslot requests, which might lead to the execution of arbitrary code.

For the old stable distribution (sarge), this problem has been fixed in version 3.0.14a-3sarge11. Packages for m68k will be provided later.

For the stable distribution (etch), this problem has been fixed in version 3.0.24-6etch9.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.3-samba", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dbg", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbfs", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"swat", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"3.0.14a-3sarge11", rls:"DEB3.1"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-samba", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dbg", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbfs", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"swat", ver:"3.0.24-6etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"3.0.24-6etch9", rls:"DEB4"))) {
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
