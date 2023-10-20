# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845376");
  script_cve_id("CVE-2021-3899", "CVE-2022-1242", "CVE-2022-28652", "CVE-2022-28654", "CVE-2022-28655", "CVE-2022-28656", "CVE-2022-28657", "CVE-2022-28658");
  script_tag(name:"creation_date", value:"2022-05-18 01:00:38 +0000 (Wed, 18 May 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5427-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5427-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-5427-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Muqing Liu and neoni discovered that Apport incorrectly handled detecting
if an executable was replaced after a crash. A local attacker could
possibly use this issue to execute arbitrary code as the root user.
(CVE-2021-3899)

Gerrit Venema discovered that Apport incorrectly handled connections to
Apport sockets inside containers. A local attacker could possibly use this
issue to connect to arbitrary sockets as the root user. (CVE-2022-1242)

Gerrit Venema discovered that Apport incorrectly handled user settings
files. A local attacker could possibly use this issue to cause Apport to
consume resources, leading to a denial of service. (CVE-2022-28652)

Gerrit Venema discovered that Apport did not limit the amount of logging
from D-Bus connections. A local attacker could possibly use this issue to
fill up the Apport log file, leading to denial of service. (CVE-2022-28654)

Gerrit Venema discovered that Apport did not filter D-Bus connection
strings. A local attacker could possibly use this issue to cause Apport to
make arbitrary network connections. (CVE-2022-28655)

Gerrit Venema discovered that Apport did not limit the amount of memory
being consumed during D-Bus connections. A local attacker could possibly
use this issue to cause Apport to consume memory, leading to a denial of
service. (CVE-2022-28656)

Gerrit Venema discovered that Apport did not disable the python crash
handler before chrooting into a container. A local attacker could possibly
use this issue to execute arbitrary code. (CVE-2022-28657)

Gerrit Venema discovered that Apport incorrectly handled filename argument
whitespace. A local attacker could possibly use this issue to spoof
arguments to the Apport daemon. (CVE-2022-28658)");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.9-0ubuntu7.28", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-apport", ver:"2.20.9-0ubuntu7.28", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.11-0ubuntu27.24", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-apport", ver:"2.20.11-0ubuntu27.24", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.11-0ubuntu71.2", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-apport", ver:"2.20.11-0ubuntu71.2", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.11-0ubuntu82.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-apport", ver:"2.20.11-0ubuntu82.1", rls:"UBUNTU22.04 LTS"))) {
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
