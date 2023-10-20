# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842260");
  script_cve_id("CVE-2014-0119", "CVE-2014-0227", "CVE-2014-0230", "CVE-2014-7810");
  script_tag(name:"creation_date", value:"2015-06-26 04:24:39 +0000 (Fri, 26 Jun 2015)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2654-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|14\.10|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2654-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2654-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7' package(s) announced via the USN-2654-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Tomcat XML parser incorrectly handled XML
External Entities (XXE). A remote attacker could possibly use this issue to
read arbitrary files. This issue only affected Ubuntu 14.04 LTS.
(CVE-2014-0119)

It was discovered that Tomcat incorrectly handled data with malformed
chunked transfer coding. A remote attacker could possibly use this issue to
conduct HTTP request smuggling attacks, or cause Tomcat to consume
resources, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS. (CVE-2014-0227)

It was discovered that Tomcat incorrectly handled HTTP responses occurring
before the entire request body was finished being read. A remote attacker
could possibly use this issue to cause a limited denial of service. This
issue only affected Ubuntu 14.04 LTS. (CVE-2014-0230)

It was discovered that the Tomcat Expression Language (EL) implementation
incorrectly handled accessible interfaces implemented by inaccessible
classes. An attacker could possibly use this issue to bypass a
SecurityManager protection mechanism. (CVE-2014-7810)");

  script_tag(name:"affected", value:"'tomcat7' package(s) on Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.55-1ubuntu0.2", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.56-2ubuntu0.1", rls:"UBUNTU15.04"))) {
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
