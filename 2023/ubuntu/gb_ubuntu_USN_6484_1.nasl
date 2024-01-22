# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6484.1");
  script_cve_id("CVE-2023-46849", "CVE-2023-46850");
  script_tag(name:"creation_date", value:"2023-11-17 04:08:50 +0000 (Fri, 17 Nov 2023)");
  script_version("2023-11-30T05:06:26+0000");
  script_tag(name:"last_modification", value:"2023-11-30 05:06:26 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-29 03:15:00 +0000 (Wed, 29 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6484-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6484-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6484-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the USN-6484-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenVPN incorrectly handled the --fragment option
in certain configurations. A remote attacker could possibly use this issue
to cause OpenVPN to crash, resulting in a denial of service.
(CVE-2023-46849)

It was discovered that OpenVPN incorrectly handled certain memory
operations. A remote attacker could use this issue to cause OpenVPN to
crash, obtain sensitive information, or possibly execute arbitrary code.
(CVE-2023-46850)");

  script_tag(name:"affected", value:"'openvpn' package(s) on Ubuntu 23.04, Ubuntu 23.10.");

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

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openvpn", ver:"2.6.1-1ubuntu1.1", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openvpn", ver:"2.6.5-0ubuntu1.1", rls:"UBUNTU23.10"))) {
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
