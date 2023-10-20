# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66606");
  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-874-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.10");

  script_xref(name:"Advisory-ID", value:"USN-874-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-874-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-3.5, xulrunner-1.9.1' package(s) announced via the USN-874-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesse Ruderman, Josh Soref, Martijn Wargers, Jose Angel, Olli Pettay, and
David James discovered several flaws in the browser and JavaScript engines
of Firefox. If a user were tricked into viewing a malicious website, a
remote attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2009-3979, CVE-2009-3980, CVE-2009-3982, CVE-2009-3986)

Takehiro Takahashi discovered flaws in the NTLM implementation in Firefox.
If an NTLM authenticated user visited a malicious website, a remote
attacker could send requests to other applications, authenticated as the
user. (CVE-2009-3983)

Jonathan Morgan discovered that Firefox did not properly display SSL
indicators under certain circumstances. This could be used by an attacker
to spoof an encrypted page, such as in a phishing attack. (CVE-2009-3984)

Jordi Chancel discovered that Firefox did not properly display invalid URLs
for a blank page. If a user were tricked into accessing a malicious
website, an attacker could exploit this to spoof the location bar, such as
in a phishing attack. (CVE-2009-3985)

David Keeler, Bob Clary, and Dan Kaminsky discovered several flaws in third
party media libraries. If a user were tricked into opening a crafted media
file, a remote attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2009-3388, CVE-2009-3389)");

  script_tag(name:"affected", value:"'firefox-3.5, xulrunner-1.9.1' package(s) on Ubuntu 9.10.");

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

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.5", ver:"3.5.6+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.6+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
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
