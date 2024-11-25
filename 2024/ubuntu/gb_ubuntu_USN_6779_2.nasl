# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6779.2");
  script_cve_id("CVE-2024-4367", "CVE-2024-4764", "CVE-2024-4767", "CVE-2024-4768", "CVE-2024-4769", "CVE-2024-4770", "CVE-2024-4771", "CVE-2024-4772", "CVE-2024-4773", "CVE-2024-4774", "CVE-2024-4775", "CVE-2024-4776", "CVE-2024-4777", "CVE-2024-4778");
  script_tag(name:"creation_date", value:"2024-05-30 04:08:53 +0000 (Thu, 30 May 2024)");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6779-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6779-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6779-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2067445");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6779-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6779-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2024-4767,
 CVE-2024-4768, CVE-2024-4769, CVE-2024-4771, CVE-2024-4772, CVE-2024-4773,
 CVE-2024-4774, CVE-2024-4775, CVE-2024-4776, CVE-2024-4777, CVE-2024-4778)

 Jan-Ivar Bruaroey discovered that Firefox did not properly manage memory
 when audio input connected with multiple consumers. An attacker could
 potentially exploit this issue to cause a denial of service, or execute
 arbitrary code. (CVE-2024-4764)

 Thomas Rinsma discovered that Firefox did not properly handle type check
 when handling fonts in PDF.js. An attacker could potentially exploit this
 issue to execute arbitrary javascript code in PDF.js. (CVE-2024-4367)

 Irvan Kurniawan discovered that Firefox did not properly handle certain
 font styles when saving a page to PDF. An attacker could potentially
 exploit this issue to cause a denial of service. (CVE-2024-4770)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"126.0.1+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
