# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841555");
  script_cve_id("CVE-2013-1718", "CVE-2013-1720", "CVE-2013-1721", "CVE-2013-1722", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");
  script_tag(name:"creation_date", value:"2013-09-24 06:18:10 +0000 (Tue, 24 Sep 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1952-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1952-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1224912");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If a user
were tricked in to opening a specially crafted message with scripting
enabled, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-1718)

Atte Kettunen discovered a flaw in the HTML5 Tree Builder when interacting
with template elements. If a user had scripting enabled, in some
circumstances an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-1720)

Alex Chapman discovered an integer overflow vulnerability in the ANGLE
library. If a user had scripting enabled, an attacker could potentially
exploit this to execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2013-1721)

Abhishek Arya discovered a use-after-free in the Animation Manager. If
a user had scripting enabled, an attacked could potentially exploit this
to execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1722)

Scott Bell discovered a use-after-free when using a select element. If
a user had scripting enabled, an attacker could potentially exploit this
to execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1724)

It was discovered that the scope of new Javascript objects could be
accessed before their compartment is initialized. If a user had scripting
enabled, an attacker could potentially exploit this to execute code with
the privileges of the user invoking Thunderbird. (CVE-2013-1725)

Dan Gohman discovered that some variables and data were used in IonMonkey,
without being initialized, which could lead to information leakage.
(CVE-2013-1728)

Sachin Shinde discovered a crash when moving some XBL-backed nodes
in to a document created by document.open(). If a user had scripting
enabled, an attacker could potentially exploit this to cause a denial
of service. (CVE-2013-1730)

Aki Helin discovered a buffer overflow when combining lists, floats and
multiple columns. If a user had scripting enabled, an attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-1732)

Two memory corruption bugs when scrolling were discovered. If a user had
scripting enabled, an attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-1735,
CVE-2013-1736)

Boris Zbarsky discovered that user-defined getters on DOM proxies would
use the expando object as 'this'. If a user had scripting enabled, an
attacker could potentially exploit this by tricking add-on code in to
making incorrect security sensitive decisions based on malicious ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.0+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.0+build1-0ubuntu0.13.04.1", rls:"UBUNTU13.04"))) {
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
