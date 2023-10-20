# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64443");
  script_cve_id("CVE-2009-1890", "CVE-2009-1891");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-802-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-802-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that mod_proxy_http did not properly handle a large
amount of streamed data when used as a reverse proxy. A remote attacker
could exploit this and cause a denial of service via memory resource
consumption. This issue affected Ubuntu 8.04 LTS, 8.10 and 9.04.
(CVE-2009-1890)

It was discovered that mod_deflate did not abort compressing large files
when the connection was closed. A remote attacker could exploit this and
cause a denial of service via CPU resource consumption. (CVE-2009-1891)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapr0", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04"))) {
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
