# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841878");
  script_cve_id("CVE-2014-0185", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-4049");
  script_tag(name:"creation_date", value:"2014-07-01 17:09:43 +0000 (Tue, 01 Jul 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|13\.10|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2254-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2254-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-2254-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Hoffmann discovered that the PHP FastCGI Process Manager (FPM)
set incorrect permissions on the UNIX socket. A local attacker could use
this issue to possibly elevate their privileges. This issue only affected
Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS. (CVE-2014-0185)

Francisco Alonso discovered that the PHP Fileinfo component incorrectly
handled certain CDF documents. A remote attacker could use this issue to
cause PHP to hang or crash, resulting in a denial of service.
(CVE-2014-0237, CVE-2014-0238)

Stefan Esser discovered that PHP incorrectly handled DNS TXT records. A
remote attacker could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2014-4049)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 13.10, Ubuntu 14.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.2-1ubuntu4.25", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.2-1ubuntu4.25", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.2-1ubuntu4.25", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.12", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.12", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.12", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.12", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.3+dfsg-1ubuntu2.4", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.3+dfsg-1ubuntu2.4", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.3+dfsg-1ubuntu2.4", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.3+dfsg-1ubuntu2.4", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.1", rls:"UBUNTU14.04 LTS"))) {
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
