# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5517");
  script_cve_id("CVE-2023-43785", "CVE-2023-43786", "CVE-2023-43787");
  script_tag(name:"creation_date", value:"2023-10-06 04:21:16 +0000 (Fri, 06 Oct 2023)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:00 +0000 (Fri, 13 Oct 2023)");

  script_name("Debian: Security Advisory (DSA-5517-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5517-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5517-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5517");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libx11");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libx11' package(s) announced via the DSA-5517-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were discovered in libx11, the X11 client-side library, which may result in denial of service or the execution of arbitrary code.

For the oldstable distribution (bullseye), these problems have been fixed in version 2:1.7.2-1+deb11u2.

For the stable distribution (bookworm), these problems have been fixed in version 2:1.8.4-2+deb12u2.

We recommend that you upgrade your libx11 packages.

For the detailed security status of libx11 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libx11' package(s) on Debian 11, Debian 12.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6-udeb", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-data", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-dev", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-doc", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-xcb-dev", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-xcb1", ver:"2:1.7.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6-udeb", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-data", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-dev", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-doc", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-xcb-dev", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-xcb1", ver:"2:1.8.4-2+deb12u2", rls:"DEB12"))) {
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
