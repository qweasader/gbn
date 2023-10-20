# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64982");
  script_cve_id("CVE-2007-6600", "CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231");
  script_tag(name:"creation_date", value:"2009-09-28 17:09:13 +0000 (Mon, 28 Sep 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-834-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-834-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.1, postgresql-8.3' package(s) announced via the USN-834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PostgreSQL could be made to unload and reload an
already loaded module by using the LOAD command. A remote authenticated
attacker could exploit this to cause a denial of service. This issue did
not affect Ubuntu 6.06 LTS. (CVE-2009-3229)

Due to an incomplete fix for CVE-2007-6600, RESET ROLE and RESET SESSION
AUTHORIZATION operations were allowed inside security-definer functions. A
remote authenticated attacker could exploit this to escalate privileges
within PostgreSQL. (CVE-2009-3230)

It was discovered that PostgreSQL did not properly perform LDAP
authentication under certain circumstances. When configured to use LDAP
with anonymous binds, a remote attacker could bypass authentication by
supplying an empty password. This issue did not affect Ubuntu 6.06 LTS.
(CVE-2009-3231)");

  script_tag(name:"affected", value:"'postgresql-8.1, postgresql-8.3' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04"))) {
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
