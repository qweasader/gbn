# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5816.2");
  script_cve_id("CVE-2023-23597", "CVE-2023-23598", "CVE-2023-23599", "CVE-2023-23601", "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23604", "CVE-2023-23605", "CVE-2023-23606");
  script_tag(name:"creation_date", value:"2023-02-06 15:16:43 +0000 (Mon, 06 Feb 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 13:51:00 +0000 (Thu, 08 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-5816-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5816-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5816-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2006075");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5816-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5816-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Niklas Baumstark discovered that a compromised web child process of Firefox
 could disable web security opening restrictions, leading to a new child
 process being spawned within the file:// context. An attacker could
 potentially exploits this to obtain sensitive information. (CVE-2023-23597)

 Tom Schuster discovered that Firefox was not performing a validation check
 on GTK drag data. An attacker could potentially exploits this to obtain
 sensitive information. (CVE-2023-23598)

 Vadim discovered that Firefox was not properly sanitizing a curl command
 output when copying a network request from the developer tools panel. An
 attacker could potentially exploits this to hide and execute arbitrary
 commands. (CVE-2023-23599)

 Luan Herrera discovered that Firefox was not stopping navigation when
 dragging a URL from a cross-origin iframe into the same tab. An attacker
 potentially exploits this to spoof the user. (CVE-2023-23601)

 Dave Vandyke discovered that Firefox did not properly implement CSP policy
 when creating a WebSocket in a WebWorker. An attacker who was able to
 inject markup into a page otherwise protected by a Content Security Policy
 may have been able to inject an executable script. (CVE-2023-23602)

 Dan Veditz discovered that Firefox did not properly implement CSP policy
 on regular expression when using console.log. An attacker potentially
 exploits this to exfiltrate data from the browser. (CVE-2023-23603)

 Nika Layzell discovered that Firefox was not performing a validation check
 when parsing a non-system html document via DOMParser::ParseFromSafeString.
 An attacker potentially exploits this to bypass web security checks.
 (CVE-2023-23604)

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2023-23605,
 CVE-2023-23606)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"109.0.1+build1-0ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"109.0.1+build1-0ubuntu0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
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
