# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843516");
  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312");
  script_tag(name:"creation_date", value:"2018-05-08 07:25:09 +0000 (Tue, 08 May 2018)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:45:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-3627-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3627-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3627-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-3627-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3627-1 fixed vulnerabilities in Apache HTTP Server. This update
provides the corresponding updates for Ubuntu 18.04 LTS.

Original advisory details:

 Alex Nichols and Jakob Hirsch discovered that the Apache HTTP Server
 mod_authnz_ldap module incorrectly handled missing charset encoding
 headers. A remote attacker could possibly use this issue to cause the
 server to crash, resulting in a denial of service. (CVE-2017-15710)

 Elar Lang discovered that the Apache HTTP Server incorrectly handled
 certain characters specified in <FilesMatch>. A remote attacker could
 possibly use this issue to upload certain files, contrary to expectations.
 (CVE-2017-15715)

 It was discovered that the Apache HTTP Server mod_session module
 incorrectly handled certain headers. A remote attacker could possibly use
 this issue to influence session data. (CVE-2018-1283)

 Robert Swiecki discovered that the Apache HTTP Server incorrectly handled
 certain requests. A remote attacker could possibly use this issue to cause
 the server to crash, leading to a denial of service. (CVE-2018-1301)

 Robert Swiecki discovered that the Apache HTTP Server mod_cache_socache
 module incorrectly handled certain headers. A remote attacker could
 possibly use this issue to cause the server to crash, leading to a denial
 of service. (CVE-2018-1303)

 Nicolas Daniels discovered that the Apache HTTP Server incorrectly
 generated the nonce when creating HTTP Digest authentication challenges.
 A remote attacker could possibly use this issue to replay HTTP requests
 across a cluster of servers. (CVE-2018-1312)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.1", rls:"UBUNTU18.04 LTS"))) {
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
