# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844413");
  script_cve_id("CVE-2020-10704");
  script_tag(name:"creation_date", value:"2020-04-30 03:01:19 +0000 (Thu, 30 Apr 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 05:15:00 +0000 (Mon, 23 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4341-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4341-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4341-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1875798");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-4341-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4341-1 fixed vulnerabilities in Samba. The updated packages for
Ubuntu 16.04 LTS introduced a regression when using LDAP. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Samba incorrectly handled certain LDAP queries. A
 remote attacker could possibly use this issue to cause Samba to consume
 resources, resulting in a denial of service. (CVE-2020-10704)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.3.11+dfsg-0ubuntu0.16.04.27", rls:"UBUNTU16.04 LTS"))) {
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
