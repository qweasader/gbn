# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705012");
  script_cve_id("CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35561", "CVE-2021-35564", "CVE-2021-35567", "CVE-2021-35578", "CVE-2021-35586", "CVE-2021-35603");
  script_tag(name:"creation_date", value:"2021-11-25 02:00:14 +0000 (Thu, 25 Nov 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-26 13:19:00 +0000 (Tue, 26 Oct 2021)");

  script_name("Debian: Security Advisory (DSA-5012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5012-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-5012-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5012");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjdk-17");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-17' package(s) announced via the DSA-5012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenJDK Java runtime, which may result in denial of service, incorrect Kerberos ticket use, selection of weak ciphers or information disclosure.

For the stable distribution (bullseye), these problems have been fixed in version 17.0.1+12-1+deb11u2.

We recommend that you upgrade your openjdk-17 packages.

For the detailed security status of openjdk-17 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openjdk-17' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-dbg", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-demo", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-doc", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-source", ver:"17.0.1+12-1+deb11u2", rls:"DEB11"))) {
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
