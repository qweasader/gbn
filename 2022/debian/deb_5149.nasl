# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705149");
  script_cve_id("CVE-2022-26691");
  script_tag(name:"creation_date", value:"2022-05-28 01:00:05 +0000 (Sat, 28 May 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 02:52:00 +0000 (Wed, 08 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-5149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5149-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5149-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5149");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cups");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-5149-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joshua Mason discovered that a logic error in the validation of the secret key used in the local authorisation mode of the CUPS printing system may result in privilege escalation.

For the oldstable distribution (buster), this problem has been fixed in version 2.2.10-6+deb10u6.

For the stable distribution (bullseye), this problem has been fixed in version 2.3.3op2-3+deb11u2.

We recommend that you upgrade your cups packages.

For the detailed security status of cups please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-bsd", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-common", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-core-drivers", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ipp-utils", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ppdc", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-server-common", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2-dev", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"2.2.10-6+deb10u6", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-bsd", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-common", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-core-drivers", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ipp-utils", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ppdc", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-server-common", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2-dev", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"2.3.3op2-3+deb11u2", rls:"DEB11"))) {
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
