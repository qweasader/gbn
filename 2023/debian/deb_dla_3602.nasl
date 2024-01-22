# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3602");
  script_cve_id("CVE-2023-43785", "CVE-2023-43786", "CVE-2023-43787");
  script_tag(name:"creation_date", value:"2023-10-06 04:21:16 +0000 (Fri, 06 Oct 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:00 +0000 (Fri, 13 Oct 2023)");

  script_name("Debian: Security Advisory (DLA-3602-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3602-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3602-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libx11");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libx11' package(s) announced via the DLA-3602-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in libx11, the X11 client-side library.

CVE-2023-43785

Gregory James Duck discovered an out of bounds memory access in _XkbReadKeySyms, which could result in denial of service.

CVE-2023-43786

Yair Mizrahi found an infinite recursion in PutSubImage when parsing a crafted file, which would result in stack exhaustion and denial of service.

CVE-2023-43787

Yair Mizrahi discovered an integer overflow in XCreateImage when parsing crafted input, which would result in a small buffer allocation leading into a buffer overflow. This could result in denial of service or potentially in arbitrary code execution.

For Debian 10 buster, these problems have been fixed in version 2:1.6.7-1+deb10u4.

We recommend that you upgrade your libx11 packages.

For the detailed security status of libx11 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libx11' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6-udeb", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-data", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-dev", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-doc", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-xcb-dev", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-xcb1", ver:"2:1.6.7-1+deb10u4", rls:"DEB10"))) {
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
