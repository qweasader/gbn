# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6476.1");
  script_cve_id("CVE-2023-46852", "CVE-2023-46853");
  script_tag(name:"creation_date", value:"2023-11-14 04:08:31 +0000 (Tue, 14 Nov 2023)");
  script_version("2023-11-15T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-11-15 05:05:25 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 19:04:00 +0000 (Tue, 07 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6476-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6476-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'memcached' package(s) announced via the USN-6476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Memcached incorrectly handled certain multiget
requests in proxy mode. A remote attacker could use this issue to cause
Memcached to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2023-46852)

It was discovered that Memcached incorrectly handled certain proxy requests
in proxy mode. A remote attacker could use this issue to cause Memcached to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2023-46853)");

  script_tag(name:"affected", value:"'memcached' package(s) on Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.6.14-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.6.18-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.6.21-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
