# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703570");
  script_cve_id("CVE-2016-3105");
  script_tag(name:"creation_date", value:"2016-05-04 22:00:00 +0000 (Wed, 04 May 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3570)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3570");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3570");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3570");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mercurial' package(s) announced via the DSA-3570 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Blake Burkhart discovered an arbitrary code execution flaw in Mercurial, a distributed version control system, when using the convert extension on Git repositories with specially crafted names. This flaw in particular affects automated code conversion services that allow arbitrary repository names.

For the stable distribution (jessie), this problem has been fixed in version 3.1.2-2+deb8u3.

For the unstable distribution (sid), this problem has been fixed in version 3.8.1-1.

We recommend that you upgrade your mercurial packages.");

  script_tag(name:"affected", value:"'mercurial' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mercurial", ver:"3.1.2-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mercurial-common", ver:"3.1.2-2+deb8u3", rls:"DEB8"))) {
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
