# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705362");
  script_cve_id("CVE-2022-37032");
  script_tag(name:"creation_date", value:"2023-02-28 02:00:12 +0000 (Tue, 28 Feb 2023)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-22 15:03:00 +0000 (Thu, 22 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-5362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5362-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5362-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5362");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/frr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'frr' package(s) announced via the DSA-5362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds read in the BGP daemon of FRRouting FRR before 8.4 may lead to a segmentation fault and denial of service. This occurs in bgp_capability_msg_parse in bgpd/bgp_packet.c.

For the stable distribution (bullseye), this problem has been fixed in version 7.5.1-1.1+deb11u1.

We recommend that you upgrade your frr packages.

For the detailed security status of frr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'frr' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"frr", ver:"7.5.1-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-doc", ver:"7.5.1-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-pythontools", ver:"7.5.1-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-rpki-rtrlib", ver:"7.5.1-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-snmp", ver:"7.5.1-1.1+deb11u1", rls:"DEB11"))) {
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
