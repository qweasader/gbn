# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843185");
  script_cve_id("CVE-2017-9022", "CVE-2017-9023");
  script_tag(name:"creation_date", value:"2017-05-31 04:50:26 +0000 (Wed, 31 May 2017)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3301-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3301-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the USN-3301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the strongSwan gmp plugin incorrectly validated RSA
public keys. A remote attacker could use this issue to cause strongSwan to
crash, resulting in a denial of service. (CVE-2017-9022)

It was discovered that strongSwan incorrectly parsed ASN.1 CHOICE types. A
remote attacker could use this issue to cause strongSwan to hang, resulting
in a denial of service. (CVE-2017-9023)");

  script_tag(name:"affected", value:"'strongswan' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.1.2-0ubuntu2.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.1.2-0ubuntu2.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-plugin-gmp", ver:"5.1.2-0ubuntu2.6", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.3.5-1ubuntu3.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.3.5-1ubuntu3.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-plugin-gmp", ver:"5.3.5-1ubuntu3.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.3.5-1ubuntu4.3", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.3.5-1ubuntu4.3", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-plugin-gmp", ver:"5.3.5-1ubuntu4.3", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.5.1-1ubuntu3.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.5.1-1ubuntu3.1", rls:"UBUNTU17.04"))) {
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
