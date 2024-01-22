# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6408.2");
  script_cve_id("CVE-2023-43786", "CVE-2023-43787", "CVE-2023-43788", "CVE-2023-43789");
  script_tag(name:"creation_date", value:"2023-10-24 04:08:28 +0000 (Tue, 24 Oct 2023)");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:00 +0000 (Fri, 13 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6408-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6408-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6408-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxpm' package(s) announced via the USN-6408-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6408-1 fixed several vulnerabilities in libXpm. This update provides
the corresponding update for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 Yair Mizrahi discovered that libXpm incorrectly handled certain malformed
 XPM image files. If a user were tricked into opening a specially crafted
 XPM image file, a remote attacker could possibly use this issue to consume
 memory, leading to a denial of service. (CVE-2023-43786)

 Yair Mizrahi discovered that libXpm incorrectly handled certain malformed
 XPM image files. If a user were tricked into opening a specially crafted
 XPM image file, a remote attacker could use this issue to cause libXpm to
 crash, leading to a denial of service, or possibly execute arbitrary code.
 (CVE-2023-43787)

 Alan Coopersmith discovered that libXpm incorrectly handled certain
 malformed XPM image files. If a user were tricked into opening a specially
 crafted XPM image file, a remote attacker could possibly use this issue to
 cause libXpm to crash, leading to a denial of service. (CVE-2023-43788,
 CVE-2023-43789)");

  script_tag(name:"affected", value:"'libxpm' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"1:3.5.10-1ubuntu0.1+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"1:3.5.11-1ubuntu0.16.04.1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"1:3.5.12-1ubuntu0.18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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
