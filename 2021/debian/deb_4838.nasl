# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704838");
  script_cve_id("CVE-2021-3181");
  script_tag(name:"creation_date", value:"2021-01-27 04:00:06 +0000 (Wed, 27 Jan 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-17 17:08:00 +0000 (Wed, 17 Feb 2021)");

  script_name("Debian: Security Advisory (DSA-4838)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4838");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4838");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4838");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mutt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mutt' package(s) announced via the DSA-4838 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered a memory leak flaw in the rfc822 group recipient parsing in Mutt, a text-based mailreader supporting MIME, GPG, PGP and threading, which could result in denial of service.

For the stable distribution (buster), this problem has been fixed in version 1.10.1-2.1+deb10u5.

We recommend that you upgrade your mutt packages.

For the detailed security status of mutt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mutt' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mutt", ver:"1.10.1-2.1+deb10u5", rls:"DEB10"))) {
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
