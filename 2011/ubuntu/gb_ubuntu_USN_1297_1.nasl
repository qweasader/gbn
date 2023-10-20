# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840830");
  script_cve_id("CVE-2011-4136", "CVE-2011-4137", "CVE-2011-4138", "CVE-2011-4139");
  script_tag(name:"creation_date", value:"2011-12-09 05:22:57 +0000 (Fri, 09 Dec 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1297-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1297-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-1297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pall McMillan discovered that Django used the root namespace when storing
cached session data. A remote attacker could exploit this to modify
sessions. (CVE-2011-4136)

Paul McMillan discovered that Django would not timeout on arbitrary URLs
when the application used URLFields. This could be exploited by a remote
attacker to cause a denial of service via resource exhaustion.
(CVE-2011-4137)

Paul McMillan discovered that while Django would check the validity of a
URL via a HEAD request, it would instead use a GET request for the target
of a redirect. This could potentially be used to trigger arbitrary GET
requests via a crafted Location header. (CVE-2011-4138)

It was discovered that Django would sometimes use a request's HTTP Host
header to construct a full URL. A remote attacker could exploit this to
conduct host header cache poisoning attacks via a crafted request.
(CVE-2011-4139)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.4", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-1ubuntu0.2.10.10.3", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.2.5-1ubuntu1.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.3-2ubuntu1.1", rls:"UBUNTU11.10"))) {
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
