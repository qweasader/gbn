# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704852");
  script_cve_id("CVE-2020-35498");
  script_tag(name:"creation_date", value:"2021-02-17 04:00:06 +0000 (Wed, 17 Feb 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-17 12:44:00 +0000 (Wed, 17 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4852-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4852-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4852");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openvswitch");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openvswitch' package(s) announced via the DSA-4852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joakim Hindersson discovered that Open vSwitch, a software-based Ethernet virtual switch, allowed a malicious user to cause a denial-of-service by sending a specially crafted packet.

For the stable distribution (buster), this problem has been fixed in version 2.10.7+ds1-0+deb10u1.

We recommend that you upgrade your openvswitch packages.

For the detailed security status of openvswitch please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dbg", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dev", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-pki", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-testcontroller", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-vtep", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-central", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-controller-vtep", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-host", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-openvswitch", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openvswitch", ver:"2.10.7+ds1-0+deb10u1", rls:"DEB10"))) {
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
