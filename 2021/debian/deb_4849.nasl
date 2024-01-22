# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704849");
  script_cve_id("CVE-2021-26910");
  script_tag(name:"creation_date", value:"2021-02-10 04:00:25 +0000 (Wed, 10 Feb 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Debian: Security Advisory (DSA-4849-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4849-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4849-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4849");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firejail");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firejail' package(s) announced via the DSA-4849-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roman Fiedler discovered a vulnerability in the OverlayFS code in firejail, a sandbox program to restrict the running environment of untrusted applications, which could result in root privilege escalation. This update disables OverlayFS support in firejail.

For the stable distribution (buster), this problem has been fixed in version 0.9.58.2-2+deb10u2.

We recommend that you upgrade your firejail packages.

For the detailed security status of firejail please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'firejail' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firejail", ver:"0.9.58.2-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firejail-profiles", ver:"0.9.58.2-2+deb10u2", rls:"DEB10"))) {
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
