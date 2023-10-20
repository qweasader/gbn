# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840733");
  script_tag(name:"creation_date", value:"2011-09-07 06:58:04 +0000 (Wed, 07 Sep 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1197-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1197-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1197-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/838322");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/837557");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/838322");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, xulrunner-1.9.2' package(s) announced via the USN-1197-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Dutch Certificate Authority DigiNotar had
mis-issued multiple fraudulent certificates. These certificates could allow
an attacker to perform a 'machine-in-the-middle' (MITM) attack which would make
the user believe their connection is secure, but is actually being
monitored.

For the protection of its users, Mozilla has removed the DigiNotar
certificate. Sites using certificates issued by DigiNotar will need to seek
another certificate vendor.

We are currently aware of a regression that blocks one of two Staat der
Nederlanden root certificates which are believed to still be secure. This
regression is being tracked at [link moved to references].");

  script_tag(name:"affected", value:"'firefox, xulrunner-1.9.2' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.21+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.21+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.21+build1+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.21+build1+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"6.0.1+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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
