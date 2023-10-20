# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840238");
  script_cve_id("CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0418", "CVE-2008-0420", "CVE-2008-0591");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-582-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-582-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-582-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird, thunderbird' package(s) announced via the USN-582-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Thunderbird did not properly set the size of a
buffer when parsing an external-body MIME-type. If a user were to open
a specially crafted email, an attacker could cause a denial of service
via application crash or possibly execute arbitrary code as the user.
(CVE-2008-0304)

Various flaws were discovered in Thunderbird and its JavaScript
engine. By tricking a user into opening a malicious message, an
attacker could execute arbitrary code with the user's privileges.
(CVE-2008-0412, CVE-2008-0413)

Various flaws were discovered in the JavaScript engine. By tricking
a user into opening a malicious message, an attacker could escalate
privileges within Thunderbird, perform cross-site scripting attacks
and/or execute arbitrary code with the user's privileges. (CVE-2008-0415)

Gerry Eisenhaur discovered that the chrome URI scheme did not properly
guard against directory traversal. Under certain circumstances, an
attacker may be able to load files or steal session data. Ubuntu is not
vulnerable in the default installation. (CVE-2008-0418)

Flaws were discovered in the BMP decoder. By tricking a user into
opening a specially crafted BMP file, an attacker could obtain
sensitive information. (CVE-2008-0420)");

  script_tag(name:"affected", value:"'mozilla-thunderbird, thunderbird' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.06.0", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.10.0", rls:"UBUNTU6.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.7.04.0", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.12+nobinonly-0ubuntu0.7.10.0", rls:"UBUNTU7.10"))) {
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
