# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840578");
  script_cve_id("CVE-2010-4351", "CVE-2011-0025");
  script_tag(name:"creation_date", value:"2011-02-04 13:19:53 +0000 (Fri, 04 Feb 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1055-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1055-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-6b18' package(s) announced via the USN-1055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that IcedTea for Java did not properly verify
signatures when handling multiply signed or partially signed JAR files,
allowing an attacker to cause code to execute that appeared to come
from a verified source. (CVE-2011-0025)

USN 1052-1 fixed a vulnerability in OpenJDK for Ubuntu 9.10 and Ubuntu
10.04 LTS on all architectures, and Ubuntu 10.10 for all architectures
except for the armel (ARM) architecture. This update provides the
corresponding update for Ubuntu 10.10 on the armel (ARM) architecture.

Original advisory details:

 It was discovered that the JNLP SecurityManager in IcedTea for Java
 OpenJDK in some instances failed to properly apply the intended
 scurity policy in its checkPermission method. This could allow
 an attacker to execute code with privileges that should have been
 prevented. (CVE-2010-4351)");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-6b18' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.5-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.5-0ubuntu1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.5-0ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
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
