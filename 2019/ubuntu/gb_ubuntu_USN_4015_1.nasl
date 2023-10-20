# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844049");
  script_cve_id("CVE-2019-12749");
  script_tag(name:"creation_date", value:"2019-06-12 02:00:36 +0000 (Wed, 12 Jun 2019)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4015-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|18\.10|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4015-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4015-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the USN-4015-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joe Vennix discovered that DBus incorrectly handled DBUS_COOKIE_SHA1
authentication. A local attacker could possibly use this issue to bypass
authentication and connect to DBus servers with elevated privileges.");

  script_tag(name:"affected", value:"'dbus' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"dbus", ver:"1.10.6-1ubuntu3.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.10.6-1ubuntu3.4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dbus", ver:"1.12.2-1ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.12.2-1ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dbus", ver:"1.12.10-1ubuntu2.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.12.10-1ubuntu2.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"dbus", ver:"1.12.12-1ubuntu1.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.12.12-1ubuntu1.1", rls:"UBUNTU19.04"))) {
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
