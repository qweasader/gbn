# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6074.2");
  script_cve_id("CVE-2023-32205", "CVE-2023-32206", "CVE-2023-32207", "CVE-2023-32208", "CVE-2023-32209", "CVE-2023-32210", "CVE-2023-32211", "CVE-2023-32212", "CVE-2023-32213", "CVE-2023-32215", "CVE-2023-32216");
  script_tag(name:"creation_date", value:"2023-05-17 04:09:42 +0000 (Wed, 17 May 2023)");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 08:25:00 +0000 (Tue, 27 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6074-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6074-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6074-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2019782");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6074-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6074-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2023-32205,
 CVE-2023-32207, CVE-2023-32210, CVE-2023-32211, CVE-2023-32212,
 CVE-2023-32213, CVE-2023-32215, CVE-2023-32216)

 Irvan Kurniawan discovered that Firefox did not properly manage memory
 when using RLBox Expat driver. An attacker could potentially exploits this
 issue to cause a denial of service. (CVE-2023-32206)

 Anne van Kesteren discovered that Firefox did not properly validate the
 import() call in service workers. An attacker could potentially exploits
 this to obtain sensitive information. (CVE-2023-32208)

 Sam Ezeh discovered that Firefox did not properly handle certain favicon
 image files. If a user were tricked into opening a malicicous favicon file,
 an attacker could cause a denial of service. (CVE-2023-32209)");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"113.0.1+build1-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"113.0.1+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
