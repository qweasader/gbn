# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841126");
  script_cve_id("CVE-2012-1177");
  script_tag(name:"creation_date", value:"2012-09-06 05:22:03 +0000 (Thu, 06 Sep 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1547-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1547-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1547-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution-data-server, libgdata' package(s) announced via the USN-1547-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vreixo Formoso discovered that the libGData library, as used
by Evolution and other applications, did not properly verify SSL
certificates. A remote attacker could exploit this to perform a man
in the middle attack to view sensitive information or alter data
transmitted via the GData protocol.");

  script_tag(name:"affected", value:"'evolution-data-server, libgdata' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgdata-google1.2-1", ver:"2.28.3.1-0ubuntu6.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdata1.2-1", ver:"2.28.3.1-0ubuntu6.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdata6", ver:"0.5.2-0ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgdata11", ver:"0.8.0-0ubuntu1.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgdata13", ver:"0.9.1-0ubuntu2.1", rls:"UBUNTU11.10"))) {
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
