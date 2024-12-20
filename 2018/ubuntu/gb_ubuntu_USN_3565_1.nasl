# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843448");
  script_cve_id("CVE-2018-6789");
  script_tag(name:"creation_date", value:"2018-02-14 07:40:54 +0000 (Wed, 14 Feb 2018)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:47:22 +0000 (Thu, 25 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-3565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3565-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3565-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim4' package(s) announced via the USN-3565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Meh Chang discovered that Exim incorrectly handled memory in certain
decoding operations. A remote attacker could use this issue to cause Exim
to crash, resulting in a denial of service, or possibly execute arbitrary
code.");

  script_tag(name:"affected", value:"'exim4' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.82-3ubuntu2.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.82-3ubuntu2.4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.86.2-2ubuntu2.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.86.2-2ubuntu2.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.89-5ubuntu1.3", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.89-5ubuntu1.3", rls:"UBUNTU17.10"))) {
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
