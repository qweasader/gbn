# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7091.2");
  script_cve_id("CVE-2024-35176", "CVE-2024-39908", "CVE-2024-41123", "CVE-2024-41946", "CVE-2024-49761");
  script_tag(name:"creation_date", value:"2024-11-21 08:42:14 +0000 (Thu, 21 Nov 2024)");
  script_version("2024-11-22T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-22 05:05:35 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 16:41:46 +0000 (Tue, 05 Nov 2024)");

  script_name("Ubuntu: Security Advisory (USN-7091-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7091-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7091-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2086615");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.7' package(s) announced via the USN-7091-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7091-1 fixed several vulnerabilities in Ruby. This update provides the
corresponding update for ruby2.7 in Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that Ruby incorrectly handled parsing of an XML document
 that has specific XML characters in an attribute value using REXML gem. An
 attacker could use this issue to cause Ruby to crash, resulting in a
 denial of service. This issue only affected in Ubuntu 22.04 LTS and Ubuntu
 24.04 LTS. (CVE-2024-35176, CVE-2024-39908, CVE-2024-41123)

 It was discovered that Ruby incorrectly handled parsing of an XML document
 that has many entity expansions with SAX2 or pull parser API. An attacker
 could use this issue to cause Ruby to crash, resulting in a denial of
 service. (CVE-2024-41946)

 It was discovered that Ruby incorrectly handled parsing of an XML document
 that has many digits in a hex numeric character reference. An attacker
 could use this issue to cause Ruby to crash, resulting in a denial of
 service. (CVE-2024-49761)");

  script_tag(name:"affected", value:"'ruby2.7' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.7", ver:"2.7.0-5ubuntu1.15", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.7", ver:"2.7.0-5ubuntu1.15", rls:"UBUNTU20.04 LTS"))) {
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
