# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841178");
  script_cve_id("CVE-2008-5983", "CVE-2010-1634", "CVE-2010-2089", "CVE-2010-3493", "CVE-2011-1015", "CVE-2011-1521", "CVE-2011-4940", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150");
  script_tag(name:"creation_date", value:"2012-10-05 04:15:35 +0000 (Fri, 05 Oct 2012)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1596-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1596-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1596-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.6' package(s) announced via the USN-1596-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python would prepend an empty string to sys.path
under certain circumstances. A local attacker with write access to the
current working directory could exploit this to execute arbitrary code.
(CVE-2008-5983)

It was discovered that the audioop module did not correctly perform input
validation. If a user or automatated system were tricked into opening a
crafted audio file, an attacker could cause a denial of service via
application crash. (CVE-2010-1634, CVE-2010-2089)

Giampaolo Rodola discovered several race conditions in the smtpd module.
A remote attacker could exploit this to cause a denial of service via
daemon outage. (CVE-2010-3493)

It was discovered that the CGIHTTPServer module did not properly perform
input validation on certain HTTP GET requests. A remote attacker could
potentially obtain access to CGI script source files. (CVE-2011-1015)

Niels Heinen discovered that the urllib and urllib2 modules would process
Location headers that specify a redirection to file: URLs. A remote
attacker could exploit this to obtain sensitive information or cause a
denial of service. This issue only affected Ubuntu 11.04. (CVE-2011-1521)

It was discovered that SimpleHTTPServer did not use a charset parameter in
the Content-Type HTTP header. An attacker could potentially exploit this
to conduct cross-site scripting (XSS) attacks against Internet Explorer 7
users. This issue only affected Ubuntu 11.04. (CVE-2011-4940)

It was discovered that Python distutils contained a race condition when
creating the ~/.pypirc file. A local attacker could exploit this to obtain
sensitive information. (CVE-2011-4944)

It was discovered that SimpleXMLRPCServer did not properly validate its
input when handling HTTP POST requests. A remote attacker could exploit
this to cause a denial of service via excessive CPU utilization.
(CVE-2012-0845)

It was discovered that Python was susceptible to hash algorithm attacks.
An attacker could cause a denial of service under certain circumstances.
This update adds the '-R' command line option and honors setting the
PYTHONHASHSEED environment variable to 'random' to salt str and datetime
objects with an unpredictable value. (CVE-2012-1150)");

  script_tag(name:"affected", value:"'python2.6' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python2.6", ver:"2.6.5-1ubuntu6.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-minimal", ver:"2.6.5-1ubuntu6.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.6", ver:"2.6.6-6ubuntu7.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-minimal", ver:"2.6.6-6ubuntu7.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.6", ver:"2.6.7-4ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.6-minimal", ver:"2.6.7-4ubuntu1.1", rls:"UBUNTU11.10"))) {
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
