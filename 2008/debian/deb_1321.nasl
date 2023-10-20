# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58426");
  script_cve_id("CVE-2007-3257");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1321");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1321");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1321");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evolution-data-server' package(s) announced via the DSA-1321 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the IMAP code in the Evolution Data Server performs insufficient sanitising of a value later used an array index, which can lead to the execution of arbitrary code.

For the oldstable distribution (sarge) a different source package is affected and will be fixed separately.

For the stable distribution (etch) this problem has been fixed in version 1.6.3-5etch1.

For the unstable distribution (sid) this problem has been fixed in version 1.10.2-2.

We recommend that you upgrade your evolution-data-server packages.");

  script_tag(name:"affected", value:"'evolution-data-server' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcamel1.2-8", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebook1.2-5", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecal1.2-6", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-cal1.2-5", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserver1.2-7", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserverui1.2-6", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegroupwise1.2-10", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexchange-storage1.2-1", ver:"1.6.3-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"1.6.3-5etch1", rls:"DEB4"))) {
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
