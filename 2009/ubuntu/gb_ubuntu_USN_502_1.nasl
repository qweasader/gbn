# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840169");
  script_cve_id("CVE-2007-3820", "CVE-2007-4224", "CVE-2007-4225");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04)");

  script_xref(name:"Advisory-ID", value:"USN-502-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-502-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdebase, kdelibs' package(s) announced via the USN-502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Konqueror could be tricked into displaying
incorrect URLs. Remote attackers could exploit this to increase their
chances of tricking a user into visiting a phishing URL, which could
lead to credential theft.");

  script_tag(name:"affected", value:"'kdebase, kdelibs' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"4:3.5.2-0ubuntu18.5", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror", ver:"4:3.5.2-0ubuntu27.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"4:3.5.5-0ubuntu3.5", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror", ver:"4:3.5.5-0ubuntu3.5", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"4:3.5.6-0ubuntu14.1", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror", ver:"4:3.5.6-0ubuntu20.2", rls:"UBUNTU7.04"))) {
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
