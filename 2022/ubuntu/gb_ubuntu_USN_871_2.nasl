# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.871.2");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-871-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-871-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-871-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/495301");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kde4libs' package(s) announced via the USN-871-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-871-1 fixed vulnerabilities in KDE. This update provides the
corresponding updates for KDE 4.

This update also fixes a directory traversal flaw in KDE when processing
help:// URLs. This issue only affected Ubuntu 8.10.

Original advisory details:

 It was discovered that the KDE libraries could use KHTML to process an
 unknown MIME type. If a user or application linked against kdelibs were
 tricked into opening a crafted file, an attacker could potentially trigger
 XMLHTTPRequests to remote sites.");

  script_tag(name:"affected", value:"'kde4libs' package(s) on Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5", ver:"4:4.1.4-0ubuntu1~intrepid1.5", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5", ver:"4:4.2.2-0ubuntu5.4", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5", ver:"4:4.3.2-0ubuntu7.2", rls:"UBUNTU9.10"))) {
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
