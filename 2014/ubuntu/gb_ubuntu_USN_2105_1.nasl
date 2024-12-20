# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841711");
  script_cve_id("CVE-2013-1069", "CVE-2013-1070");
  script_tag(name:"creation_date", value:"2014-02-17 06:10:03 +0000 (Mon, 17 Feb 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2105-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2105-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maas' package(s) announced via the USN-2105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Troup discovered that MAAS stored RabbitMQ authentication
credentials in a world-readable file. A local authenticated user
could read this password and potentially gain privileges of other
user accounts. This update restricts the file permissions to prevent
unintended access. (CVE-2013-1069)

Chris Glass discovered that the MAAS API was vulnerable to cross-site
scripting vulnerabilities. With cross-site scripting vulnerabilities,
if a user were tricked into viewing a specially crafted page, a remote
attacker could exploit this to modify the contents, or steal confidential
data, within the same domain. (CVE-2013-1070)");

  script_tag(name:"affected", value:"'maas' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"maas-region-controller", ver:"1.2+bzr1373+dfsg-0ubuntu1~12.04.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-maas", ver:"1.2+bzr1373+dfsg-0ubuntu1~12.04.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"maas-region-controller", ver:"1.2+bzr1373+dfsg-0ubuntu1.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-maas", ver:"1.2+bzr1373+dfsg-0ubuntu1.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"maas-region-controller", ver:"1.4+bzr1693+dfsg-0ubuntu2.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-maas", ver:"1.4+bzr1693+dfsg-0ubuntu2.3", rls:"UBUNTU13.10"))) {
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
