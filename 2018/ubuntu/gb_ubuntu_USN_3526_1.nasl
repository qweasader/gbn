# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843754");
  script_cve_id("CVE-2017-12173");
  script_tag(name:"creation_date", value:"2018-10-26 04:15:27 +0000 (Fri, 26 Oct 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3526-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3526-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3526-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the USN-3526-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SSSD incorrectly handled certain inputs when querying
its local cache. An attacker could use this to inject arbitrary code and expose
sensitive information.");

  script_tag(name:"affected", value:"'sssd' package(s) on Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sssd", ver:"1.13.4-1ubuntu1.10", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-common", ver:"1.13.4-1ubuntu1.10", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-tools", ver:"1.13.4-1ubuntu1.10", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sssd", ver:"1.15.2-1ubuntu1.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-common", ver:"1.15.2-1ubuntu1.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-tools", ver:"1.15.2-1ubuntu1.1", rls:"UBUNTU17.04"))) {
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
