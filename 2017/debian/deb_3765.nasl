# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703765");
  script_cve_id("CVE-2017-5331", "CVE-2017-5332", "CVE-2017-5333");
  script_tag(name:"creation_date", value:"2017-01-13 23:00:00 +0000 (Fri, 13 Jan 2017)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 19:59:00 +0000 (Thu, 07 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-3765)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3765");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3765");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3765");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icoutils' package(s) announced via the DSA-3765 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several programming errors in the wrestool tool of icoutils, a suite of tools to create and extract MS Windows icons and cursors, allow denial of service or the execution of arbitrary code if a malformed binary is parsed.

For the stable distribution (jessie), these problems have been fixed in version 0.31.0-2+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 0.31.1-1.

For the unstable distribution (sid), these problems have been fixed in version 0.31.1-1.

We recommend that you upgrade your icoutils packages.");

  script_tag(name:"affected", value:"'icoutils' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icoutils", ver:"0.31.0-2+deb8u2", rls:"DEB8"))) {
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
