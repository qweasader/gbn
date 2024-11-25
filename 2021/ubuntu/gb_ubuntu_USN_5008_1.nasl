# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844995");
  script_cve_id("CVE-2021-3468", "CVE-2021-3502");
  script_tag(name:"creation_date", value:"2021-07-08 03:00:22 +0000 (Thu, 08 Jul 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-17 17:30:25 +0000 (Mon, 17 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-5008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|20\.10|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-5008-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5008-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi' package(s) announced via the USN-5008-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Kremer discovered that Avahi incorrectly handled termination signals
on the Unix socket. A local attacker could possibly use this issue to cause
Avahi to hang, resulting in a denial of service. This issue only affected
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10. (CVE-2021-3468)

It was discovered that Avahi incorrectly handled certain hostnames. A local
attacker could possibly use this issue to cause Avahi to crash, resulting
in a denial of service. This issue only affected Ubuntu 20.10 and Ubuntu
21.04. (CVE-2021-3502)");

  script_tag(name:"affected", value:"'avahi' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.7-3.1ubuntu1.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-core7", ver:"0.7-3.1ubuntu1.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.7-4ubuntu7.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-core7", ver:"0.7-4ubuntu7.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.8-3ubuntu1.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-core7", ver:"0.8-3ubuntu1.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.8-5ubuntu3.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-core7", ver:"0.8-5ubuntu3.1", rls:"UBUNTU21.04"))) {
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
