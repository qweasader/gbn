# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844401");
  script_cve_id("CVE-2018-1000876", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-12641", "CVE-2018-12697", "CVE-2018-12698", "CVE-2018-12699", "CVE-2018-12700", "CVE-2018-12934", "CVE-2018-13033", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360", "CVE-2018-17794", "CVE-2018-17985", "CVE-2018-18309", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-18700", "CVE-2018-18701", "CVE-2018-19931", "CVE-2018-19932", "CVE-2018-20002", "CVE-2018-20623", "CVE-2018-20651", "CVE-2018-20671", "CVE-2018-8945", "CVE-2018-9138", "CVE-2019-12972", "CVE-2019-14250", "CVE-2019-14444", "CVE-2019-17450", "CVE-2019-17451", "CVE-2019-9070", "CVE-2019-9071", "CVE-2019-9073", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077");
  script_tag(name:"creation_date", value:"2020-04-23 03:00:27 +0000 (Thu, 23 Apr 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-21 15:34:10 +0000 (Tue, 21 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-4336-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4336-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4336-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the USN-4336-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNU binutils contained a large number of security
issues. If a user or automated system were tricked into processing a
specially-crafted file, a remote attacker could cause GNU binutils to
crash, resulting in a denial of service, or possibly execute arbitrary
code.");

  script_tag(name:"affected", value:"'binutils' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.30-21ubuntu1~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.30-21ubuntu1~18.04.3", rls:"UBUNTU18.04 LTS"))) {
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
