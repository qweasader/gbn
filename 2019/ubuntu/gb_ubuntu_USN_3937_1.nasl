# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843965");
  script_cve_id("CVE-2018-17189", "CVE-2018-17199", "CVE-2019-0196", "CVE-2019-0211", "CVE-2019-0217", "CVE-2019-0220");
  script_tag(name:"creation_date", value:"2019-04-05 02:00:26 +0000 (Fri, 05 Apr 2019)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-3937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3937-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3937-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-3937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Charles Fol discovered that the Apache HTTP Server incorrectly handled the
scoreboard shared memory area. A remote attacker able to upload and run
scripts could possibly use this issue to execute arbitrary code with root
privileges. (CVE-2019-0211)

It was discovered that the Apache HTTP Server HTTP/2 module incorrectly
handled certain requests. A remote attacker could possibly use this issue
to cause the server to consume resources, leading to a denial of service.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2018-17189)

It was discovered that the Apache HTTP Server incorrectly handled session
expiry times. When used with mod_session_cookie, this may result in the
session expiry time to be ignored, contrary to expectations.
(CVE-2018-17199)

Craig Young discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled certain requests. A remote attacker could possibly use
this issue to cause the server to process requests incorrectly. This issue
only affected Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2019-0196)

Simon Kappel discovered that the Apache HTTP Server mod_auth_digest module
incorrectly handled threads. A remote attacker with valid credentials could
possibly use this issue to authenticate using another username, bypassing
access control restrictions. (CVE-2019-0217)

Bernhard Lorenz discovered that the Apache HTTP Server was inconsistent
when processing requests containing multiple consecutive slashes. This
could lead to directives such as LocationMatch and RewriteRule to perform
contrary to expectations. (CVE-2019-0220)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.7-1ubuntu4.22", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.18-2ubuntu3.10", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.34-1ubuntu2.1", rls:"UBUNTU18.10"))) {
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
