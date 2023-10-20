# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705085");
  script_cve_id("CVE-2022-25235", "CVE-2022-25236", "CVE-2022-25313", "CVE-2022-25314", "CVE-2022-25315");
  script_tag(name:"creation_date", value:"2022-02-23 02:00:07 +0000 (Wed, 23 Feb 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 18:46:00 +0000 (Fri, 25 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5085)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5085");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5085");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5085");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/expat");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'expat' package(s) announced via the DSA-5085 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Expat, an XML parsing C library, which could result in denial of service or potentially the execution of arbitrary code, if a malformed XML file is processed.

For the oldstable distribution (buster), these problems have been fixed in version 2.2.6-2+deb10u3.

For the stable distribution (bullseye), these problems have been fixed in version 2.2.10-2+deb11u2.

We recommend that you upgrade your expat packages.

For the detailed security status of expat please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'expat' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"expat", ver:"2.2.6-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.2.6-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-dev", ver:"2.2.6-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"2.2.6-2+deb10u3", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"expat", ver:"2.2.10-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.2.10-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-dev", ver:"2.2.10-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"2.2.10-2+deb11u2", rls:"DEB11"))) {
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
