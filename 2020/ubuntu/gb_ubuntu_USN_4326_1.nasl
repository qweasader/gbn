# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844390");
  script_cve_id("CVE-2018-12641", "CVE-2018-12697", "CVE-2018-12698", "CVE-2018-12934", "CVE-2018-17794", "CVE-2018-17985", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18700", "CVE-2018-18701", "CVE-2018-9138", "CVE-2019-14250", "CVE-2019-9070", "CVE-2019-9071");
  script_tag(name:"creation_date", value:"2020-04-09 03:00:29 +0000 (Thu, 09 Apr 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 19:22:00 +0000 (Fri, 10 Dec 2021)");

  script_name("Ubuntu: Security Advisory (USN-4326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4326-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4326-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libiberty' package(s) announced via the USN-4326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libiberty incorrectly handled parsing certain
binaries. If a user or automated system were tricked into processing a
specially crafted binary, a remote attacker could use this issue to cause
libiberty to crash, resulting in a denial of service, or possibly execute
arbitrary code");

  script_tag(name:"affected", value:"'libiberty' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libiberty-dev", ver:"20160215-1ubuntu0.3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libiberty-dev", ver:"20170913-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
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
