# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705206");
  script_cve_id("CVE-2021-37150", "CVE-2022-25763", "CVE-2022-28129", "CVE-2022-31778", "CVE-2022-31779", "CVE-2022-31780");
  script_tag(name:"creation_date", value:"2022-08-14 01:00:12 +0000 (Sun, 14 Aug 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-13 03:15:00 +0000 (Sat, 13 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5206)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5206");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5206");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5206");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/trafficserver");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'trafficserver' package(s) announced via the DSA-5206 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Apache Traffic Server, a reverse and forward proxy server, which could result in HTTP request smuggling, cache poisoning or information disclosure.

For the stable distribution (bullseye), these problems have been fixed in version 8.1.5+ds-1~deb11u1.

We recommend that you upgrade your trafficserver packages.

For the detailed security status of trafficserver please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"trafficserver", ver:"8.1.5+ds-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"trafficserver-dev", ver:"8.1.5+ds-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"trafficserver-experimental-plugins", ver:"8.1.5+ds-1~deb11u1", rls:"DEB11"))) {
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
