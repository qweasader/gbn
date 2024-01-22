# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71492");
  script_cve_id("CVE-2012-0217");
  script_tag(name:"creation_date", value:"2012-08-10 07:13:49 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2508-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2508-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2508-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2508");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-8' package(s) announced via the DSA-2508-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rafal Wojtczuk from Bromium discovered that FreeBSD wasn't handling correctly uncanonical return addresses on Intel amd64 CPUs, allowing privilege escalation to kernel for local users.

For the stable distribution (squeeze), this problem has been fixed in version 8.1+dfsg-8+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in version 8.3-4.

For the unstable distribution (sid), this problem has been fixed in version 8.3-4.

We recommend that you upgrade your kfreebsd-8 packages.");

  script_tag(name:"affected", value:"'kfreebsd-8' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8-486", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8-686", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8-686-smp", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8-amd64", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8.1-1", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8.1-1-486", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8.1-1-686", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8.1-1-686-smp", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-8.1-1-amd64", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8-486", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8-686", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8-686-smp", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8-amd64", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8.1-1-486", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8.1-1-686", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8.1-1-686-smp", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-8.1-1-amd64", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-source-8.1", ver:"8.1+dfsg-8+squeeze3", rls:"DEB6"))) {
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
