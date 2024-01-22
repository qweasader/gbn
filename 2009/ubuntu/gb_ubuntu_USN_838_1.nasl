# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65010");
  script_cve_id("CVE-2008-4577", "CVE-2008-5301", "CVE-2009-2632", "CVE-2009-3235");
  script_tag(name:"creation_date", value:"2009-10-06 00:49:40 +0000 (Tue, 06 Oct 2009)");
  script_version("2024-01-22T05:07:31+0000");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 02:46:00 +0000 (Sun, 21 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-838-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-838-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-838-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the USN-838-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ACL plugin in Dovecot would incorrectly handle
negative access rights. An attacker could exploit this flaw to access the
Dovecot server, bypassing the intended access restrictions. This only
affected Ubuntu 8.04 LTS. (CVE-2008-4577)

It was discovered that the ManageSieve service in Dovecot incorrectly
handled '..' in script names. A remote attacker could exploit this to read
and modify arbitrary sieve files on the server. This only affected Ubuntu
8.10. (CVE-2008-5301)

It was discovered that the Sieve plugin in Dovecot incorrectly handled
certain sieve scripts. An authenticated user could exploit this with a
crafted sieve script to cause a denial of service or possibly execute
arbitrary code. (CVE-2009-2632, CVE-2009-3235)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1:1.0.10-1ubuntu5.2", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1:1.1.4-0ubuntu1.3", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1:1.1.11-0ubuntu4.1", rls:"UBUNTU9.04"))) {
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
