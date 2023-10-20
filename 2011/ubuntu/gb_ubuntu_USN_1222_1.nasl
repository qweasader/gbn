# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840759");
  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2997", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3004", "CVE-2011-3005", "CVE-2011-3232");
  script_tag(name:"creation_date", value:"2011-09-30 14:02:57 +0000 (Fri, 30 Sep 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1222-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1222-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Benjamin Smedberg, Bob Clary, Jesse Ruderman, Bob Clary, Andrew McCreight,
Andreas Gal, Gary Kwong, Igor Bukanov, Jason Orendorff, Jesse Ruderman, and
Marcia Knous discovered multiple memory vulnerabilities in the browser
rendering engine. An attacker could use these to possibly execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2011-2995,
CVE-2011-2997)

Boris Zbarsky discovered that a frame named 'location' could shadow the
window.location object unless a script in a page grabbed a reference to the
true object before the frame was created. This is in violation of the Same
Origin Policy. A malicious website could possibly use this to access
another website or the local file system. (CVE-2011-2999)

Ian Graham discovered that when multiple Location headers were present,
Firefox would use the second one resulting in a possible CRLF injection
attack. CRLF injection issues can result in a wide variety of attacks, such
as XSS (Cross-Site Scripting) vulnerabilities, browser cache poisoning, and
cookie theft. (CVE-2011-3000)

Mariusz Mlynski discovered that if the user could be convinced to hold down
the enter key, a malicious website could potential pop up a download dialog
and the default open action would be selected or lead to the installation
of an arbitrary add-on. This would result in potentially malicious content
being run with privileges of the user invoking Firefox. (CVE-2011-2372,
CVE-2011-3001)

Michael Jordon and Ben Hawkes discovered flaws in WebGL. If a user were
tricked into opening a malicious page, an attacker could cause the browser
to crash. (CVE-2011-3002, CVE-2011-3003)

It was discovered that Firefox did not properly free memory when processing
ogg files. If a user were tricked into opening a malicious page, an
attacker could cause the browser to crash. (CVE-2011-3005)

David Rees and Aki Helin discovered a problem in the JavaScript engine. An
attacker could exploit this to crash the browser or potentially escalate
privileges within the browser. (CVE-2011-3232)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"7.0.1+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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
