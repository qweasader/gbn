# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704710");
  script_cve_id("CVE-2020-9494");
  script_tag(name:"creation_date", value:"2020-06-28 03:00:06 +0000 (Sun, 28 Jun 2020)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-11 21:23:00 +0000 (Thu, 11 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4710-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4710-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4710-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4710");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/trafficserver");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'trafficserver' package(s) announced via the DSA-4710-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in Apache Traffic Server, a reverse and forward proxy server, which could result in denial of service via malformed HTTP/2 headers.

For the stable distribution (buster), this problem has been fixed in version 8.0.2+ds-1+deb10u3.

We recommend that you upgrade your trafficserver packages.

For the detailed security status of trafficserver please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"trafficserver", ver:"8.0.2+ds-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"trafficserver-dev", ver:"8.0.2+ds-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"trafficserver-experimental-plugins", ver:"8.0.2+ds-1+deb10u3", rls:"DEB10"))) {
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
