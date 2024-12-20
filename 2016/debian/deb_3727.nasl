# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703727");
  script_cve_id("CVE-2016-4330", "CVE-2016-4331", "CVE-2016-4332", "CVE-2016-4333");
  script_tag(name:"creation_date", value:"2016-12-02 11:57:07 +0000 (Fri, 02 Dec 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-22 02:06:45 +0000 (Tue, 22 Nov 2016)");

  script_name("Debian: Security Advisory (DSA-3727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3727-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3727-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3727");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hdf5' package(s) announced via the DSA-3727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cisco Talos discovered that hdf5, a file format and library for storing scientific data, contained several vulnerabilities that could lead to arbitrary code execution when handling untrusted data.

For the stable distribution (jessie), these problems have been fixed in version 1.8.13+docs-15+deb8u1.

For the testing distribution (stretch) and unstable distribution (sid), these problems have been fixed in version 1.10.0-patch1+docs-1.

We recommend that you upgrade your hdf5 packages.");

  script_tag(name:"affected", value:"'hdf5' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"hdf5-helpers", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hdf5-tools", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-8", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-8-dbg", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-cpp-8", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-cpp-8-dbg", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-dev", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-doc", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-mpi-dev", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-mpich-8", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-mpich-8-dbg", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-mpich-dev", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-mpich2-dev", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-openmpi-8", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-openmpi-8-dbg", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-openmpi-dev", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdf5-serial-dev", ver:"1.8.13+docs-15+deb8u1", rls:"DEB8"))) {
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
