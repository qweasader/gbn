# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840852");
  script_cve_id("CVE-2010-3493", "CVE-2011-1521");
  script_tag(name:"creation_date", value:"2011-12-23 05:05:41 +0000 (Fri, 23 Dec 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1314-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1314-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.1, python3.2' package(s) announced via the USN-1314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Giampaolo Rodola discovered that the smtpd module in Python 3 did not
properly handle certain error conditions. A remote attacker could exploit
this to cause a denial of service via daemon outage. This issue only
affected Ubuntu 10.04 LTS. (CVE-2010-3493)

Niels Heinen discovered that the urllib module in Python 3 would process
Location headers that specify a file:// URL. A remote attacker could use
this to obtain sensitive information or cause a denial of service via
resource consumption. (CVE-2011-1521)");

  script_tag(name:"affected", value:"'python3.1, python3.2' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.2-0ubuntu3.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.2+20100915-0ubuntu4.1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.3-1ubuntu1.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2-minimal", ver:"3.2-1ubuntu1.1", rls:"UBUNTU11.04"))) {
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
