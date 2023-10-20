# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705319");
  script_cve_id("CVE-2022-4337", "CVE-2022-4338");
  script_tag(name:"creation_date", value:"2023-01-15 02:00:06 +0000 (Sun, 15 Jan 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-14 04:36:00 +0000 (Sat, 14 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-5319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5319");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5319");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5319");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openvswitch");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openvswitch' package(s) announced via the DSA-5319 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the LLPD implementation of Open vSwitch, software-based Ethernet virtual switch, which could result in denial of service.

For the stable distribution (bullseye), these problems have been fixed in version 2.15.0+ds1-2+deb11u2.

We recommend that you upgrade your openvswitch packages.

For the detailed security status of openvswitch please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dbg", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dev", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-ipsec", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-pki", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch-dpdk", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-testcontroller", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-vtep", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openvswitch", ver:"2.15.0+ds1-2+deb11u2", rls:"DEB11"))) {
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
