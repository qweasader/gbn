# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5412");
  script_cve_id("CVE-2021-32142", "CVE-2023-1729");
  script_tag(name:"creation_date", value:"2023-05-29 04:22:35 +0000 (Mon, 29 May 2023)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-14 18:31:00 +0000 (Tue, 14 Mar 2023)");

  script_name("Debian: Security Advisory (DSA-5412-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5412-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5412-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5412");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libraw");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libraw' package(s) announced via the DSA-5412-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libraw, a library for reading RAW files obtained from digital photo cameras, which may result in denial of service or the execution of arbitrary code if specially crafted files are processed.

For the stable distribution (bullseye), these problems have been fixed in version 0.20.2-1+deb11u1.

We recommend that you upgrade your libraw packages.

For the detailed security status of libraw please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libraw' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libraw-bin", ver:"0.20.2-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libraw-dev", ver:"0.20.2-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libraw-doc", ver:"0.20.2-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libraw20", ver:"0.20.2-1+deb11u1", rls:"DEB11"))) {
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
