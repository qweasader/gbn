# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705052");
  script_cve_id("CVE-2022-23220");
  script_tag(name:"creation_date", value:"2022-01-22 02:00:12 +0000 (Sat, 22 Jan 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 18:10:00 +0000 (Thu, 27 Jan 2022)");

  script_name("Debian: Security Advisory (DSA-5052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5052");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5052");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5052");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/usbview");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'usbview' package(s) announced via the DSA-5052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthias Gerstner reported that usbview, a USB device viewer, does not properly handle authorization in the PolicyKit policy configuration, which could result in root privilege escalation.

For the oldstable distribution (buster), this problem has been fixed in version 2.0-21-g6fe2f4f-2+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 2.0-21-g6fe2f4f-2+deb11u1.

We recommend that you upgrade your usbview packages.

For the detailed security status of usbview please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'usbview' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"usbview", ver:"2.0-21-g6fe2f4f-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"usbview", ver:"2.0-21-g6fe2f4f-2+deb11u1", rls:"DEB11"))) {
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
