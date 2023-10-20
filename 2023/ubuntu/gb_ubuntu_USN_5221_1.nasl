# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5221.1");
  script_cve_id("CVE-2021-21309", "CVE-2021-32626", "CVE-2021-32627", "CVE-2021-32628", "CVE-2021-32672", "CVE-2021-32675", "CVE-2021-32687", "CVE-2021-32761", "CVE-2021-41099");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-13 16:04:00 +0000 (Wed, 13 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5221-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5221-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5221-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the USN-5221-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Redis incorrectly handled certain specially crafted
Lua scripts. A remote attacker could possibly use this issue to cause a
denial of service or execute arbitrary code. (CVE-2021-32626)

It was discovered that Redis incorrectly handled some malformed requests
when using Redis Lua Debugger. A remote attacker could possibly use this
issue to cause a denial of service or other unspecified impact. This issue
only affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2021-32672)

It was discovered that Redis incorrectly handled certain Redis Standard
Protocol (RESP) requests. A remote attacker could possibly use this issue
to cause a denial of service. (CVE-2021-32675)

It was discovered that Redis incorrectly handled some configuration
parameters with specially crafted network payloads. A remote attacker
could possibly use this issue to cause a denial of service or execute
arbitrary code. Vulnerabilities CVE-2021-32627 and CVE-2021-41099
only affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
(CVE-2021-32627, CVE-2021-32628, CVE-2021-32687, CVE-2021-41099).

It was discovered that Redis incorrectly handled memory when processing
certain input in 32-bit systems. A remote attacker could possibly use
this issue to cause a denial of service or execute arbitrary code.
One vulnerability (CVE-2021-32761) only affected Ubuntu 14.04 ESM,
Ubuntu 16.04 ESM and Ubuntu 18.04 ESM and another vulnerability
(CVE-2021-21309) only affected Ubuntu 18.04 ESM.
(CVE-2021-32761, CVE-2021-21309).");

  script_tag(name:"affected", value:"'redis' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"2:2.8.4-2ubuntu0.2+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"2:2.8.4-2ubuntu0.2+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"2:3.0.6-1ubuntu0.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"2:3.0.6-1ubuntu0.4+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis", ver:"5:4.0.9-1ubuntu0.2+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"5:4.0.9-1ubuntu0.2+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redis", ver:"5:5.0.7-2ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"5:5.0.7-2ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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
