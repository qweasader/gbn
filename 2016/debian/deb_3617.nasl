# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703617");
  script_cve_id("CVE-2015-3219", "CVE-2016-4428");
  script_tag(name:"creation_date", value:"2016-07-05 22:00:00 +0000 (Tue, 05 Jul 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-09 15:08:00 +0000 (Tue, 09 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-3617)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3617");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3617");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3617");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'horizon' package(s) announced via the DSA-3617 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two cross-site scripting vulnerabilities have been found in Horizon, a web application to control an OpenStack cloud.

For the stable distribution (jessie), these problems have been fixed in version 2014.1.3-7+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 3:9.0.1-2.

For the unstable distribution (sid), these problems have been fixed in version 3:9.0.1-2.

We recommend that you upgrade your horizon packages.");

  script_tag(name:"affected", value:"'horizon' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openstack-dashboard", ver:"2014.1.3-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openstack-dashboard-apache", ver:"2014.1.3-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-horizon", ver:"2014.1.3-7+deb8u2", rls:"DEB8"))) {
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
