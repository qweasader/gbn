# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5269.2");
  script_cve_id("CVE-2022-22818", "CVE-2022-23833");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 20:31:52 +0000 (Mon, 07 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5269-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5269-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5269-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-5269-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5269-1 fixed several vulnerabilities in Django. This update provides
the corresponding update for Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.

Original advisory details:

 Keryn Knight discovered that Django incorrectly handled certain template
 tags. A remote attacker could possibly use this issue to perform a
 cross-site scripting attack. (CVE-2022-22818)

 Alan Ryan discovered that Django incorrectly handled file uploads. A remote
 attacker could possibly use this issue to cause Django to hang, resulting
 in a denial of service. (CVE-2022-23833)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.6.11-0ubuntu1.3+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.8.7-1ubuntu5.15+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1.8.7-1ubuntu5.15+esm4", rls:"UBUNTU16.04 LTS"))) {
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
