# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703825");
  script_cve_id("CVE-2016-3822");
  script_tag(name:"creation_date", value:"2017-03-30 22:00:00 +0000 (Thu, 30 Mar 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-05 20:33:00 +0000 (Mon, 05 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-3825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3825-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3825-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3825");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jhead' package(s) announced via the DSA-3825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that jhead, a tool to manipulate the non-image part of EXIF compliant JPEG files, is prone to an out-of-bounds access vulnerability, which may result in denial of service or, potentially, the execution of arbitrary code if an image with specially crafted EXIF data is processed.

For the stable distribution (jessie), this problem has been fixed in version 1:2.97-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been fixed in version 1:3.00-4.

For the unstable distribution (sid), this problem has been fixed in version 1:3.00-4.

We recommend that you upgrade your jhead packages.");

  script_tag(name:"affected", value:"'jhead' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"jhead", ver:"1:2.97-1+deb8u1", rls:"DEB8"))) {
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
