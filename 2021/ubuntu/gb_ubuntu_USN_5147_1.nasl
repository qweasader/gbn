# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845134");
  script_cve_id("CVE-2017-17087", "CVE-2019-20807", "CVE-2021-3872", "CVE-2021-3903", "CVE-2021-3927", "CVE-2021-3928");
  script_tag(name:"creation_date", value:"2021-11-16 02:00:30 +0000 (Tue, 16 Nov 2021)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-10 05:15:00 +0000 (Wed, 10 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-5147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|21\.04|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5147-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5147-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-5147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim incorrectly handled permissions on the .swp
file. A local attacker could possibly use this issue to obtain sensitive
information. This issue only affected Ubuntu 14.04 ESM. (CVE-2017-17087)

It was discovered that Vim incorrectly handled restricted mode. A local
attacker could possibly use this issue to bypass restricted mode and
execute arbitrary commands. Note: This update only makes executing shell
commands more difficult. Restricted mode should not be considered a
complete security measure. This issue only affected Ubuntu 14.04 ESM.
(CVE-2019-20807)

Brian Carpenter discovered that vim incorrectly handled memory
when opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. This issue only affected
Ubuntu 20.04 LTS, Ubuntu 21.04 and Ubuntu 21.10. (CVE-2021-3872)

It was discovered that vim incorrectly handled memory when
opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. (CVE-2021-3903)

It was discovered that vim incorrectly handled memory when
opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. (CVE-2021-3927)

It was discovered that vim incorrectly handled memory when
opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. (CVE-2021-3928)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.052-1ubuntu3.1+esm4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.1689-3ubuntu1.5+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.1453-1ubuntu1.7", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.1.2269-1ubuntu5.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.2.2434-1ubuntu1.2", rls:"UBUNTU21.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.2.2434-3ubuntu3.1", rls:"UBUNTU21.10"))) {
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
