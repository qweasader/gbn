# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5455");
  script_cve_id("CVE-2023-38403");
  script_tag(name:"creation_date", value:"2023-07-18 04:28:45 +0000 (Tue, 18 Jul 2023)");
  script_version("2023-08-17T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-08-17 05:05:20 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 17:26:00 +0000 (Tue, 15 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5455");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5455");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5455");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/iperf3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iperf3' package(s) announced via the DSA-5455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A memory allocation issue was found in iperf3, the Internet Protocol bandwidth measuring tool, that could cause denial of service when encontering certain invalid length value in TCP packet.

For the oldstable distribution (bullseye), this problem has been fixed in version 3.9-1+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 3.12-1+deb12u1.

We recommend that you upgrade your iperf3 packages.

For the detailed security status of iperf3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'iperf3' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"iperf3", ver:"3.9-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf-dev", ver:"3.9-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf0", ver:"3.9-1+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"iperf3", ver:"3.12-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf-dev", ver:"3.12-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf0", ver:"3.12-1+deb12u1", rls:"DEB12"))) {
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
