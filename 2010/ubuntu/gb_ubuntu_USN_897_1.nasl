# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840384");
  script_cve_id("CVE-2008-4098", "CVE-2008-4456", "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4030", "CVE-2009-4484");
  script_tag(name:"creation_date", value:"2010-02-15 15:07:49 +0000 (Mon, 15 Feb 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-897-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-897-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-897-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) announced via the USN-897-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MySQL could be made to overwrite existing table
files in the data directory. An authenticated user could use the DATA
DIRECTORY and INDEX DIRECTORY options to possibly bypass privilege checks.
This update alters table creation behaviour by disallowing the use of the
MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY options. This
issue only affected Ubuntu 8.10. (CVE-2008-4098)

It was discovered that MySQL contained a cross-site scripting vulnerability
in the command-line client when the --html option is enabled. An attacker
could place arbitrary web script or html in a database cell, which would
then get placed in the html document output by the command-line tool. This
issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 8.10 and 9.04.
(CVE-2008-4456)

It was discovered that MySQL could be made to overwrite existing table
files in the data directory. An authenticated user could use symlinks
combined with the DATA DIRECTORY and INDEX DIRECTORY options to possibly
bypass privilege checks. This issue only affected Ubuntu 9.10.
(CVE-2008-7247)

It was discovered that MySQL contained multiple format string flaws when
logging database creation and deletion. An authenticated user could use
specially crafted database names to make MySQL crash, causing a denial of
service. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 8.10 and 9.04.
(CVE-2009-2446)

It was discovered that MySQL incorrectly handled errors when performing
certain SELECT statements, and did not preserve correct flags when
performing statements that use the GeomFromWKB function. An authenticated
user could exploit this to make MySQL crash, causing a denial of service.
(CVE-2009-4019)

It was discovered that MySQL incorrectly checked symlinks when using the
DATA DIRECTORY and INDEX DIRECTORY options. A local user could use symlinks
to create tables that pointed to tables known to be created at a later
time, bypassing access restrictions. (CVE-2009-4030)

It was discovered that MySQL contained a buffer overflow when parsing
ssl certificates. A remote attacker could send crafted requests and cause a
denial of service or possibly execute arbitrary code. This issue did not
affect Ubuntu 6.06 LTS and the default compiler options for affected
releases should reduce the vulnerability to a denial of service. In the
default installation, attackers would also be isolated by the AppArmor
MySQL profile. (CVE-2009-4484)");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10"))) {
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
