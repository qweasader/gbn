# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705291");
  script_cve_id("CVE-2022-30974", "CVE-2022-30975", "CVE-2022-44789");
  script_tag(name:"creation_date", value:"2022-11-30 02:00:11 +0000 (Wed, 30 Nov 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-29 20:50:00 +0000 (Tue, 29 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-5291)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5291");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5291");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5291");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mujs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mujs' package(s) announced via the DSA-5291 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MuJS, a lightweight JavaScript interpreter, which could result in denial of service and potentially the execution of arbitrary code.

For the stable distribution (bullseye), these problems have been fixed in version 1.1.0-1+deb11u2.

We recommend that you upgrade your mujs packages.

For the detailed security status of mujs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mujs' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmujs-dev", ver:"1.1.0-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmujs1", ver:"1.1.0-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mujs", ver:"1.1.0-1+deb11u2", rls:"DEB11"))) {
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
