# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0125");
  script_cve_id("CVE-2023-25809", "CVE-2023-27561", "CVE-2023-28642");
  script_tag(name:"creation_date", value:"2023-04-07 04:12:44 +0000 (Fri, 07 Apr 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-06 17:45:00 +0000 (Thu, 06 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0125)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0125");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0125.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31729");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3369");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/issues/3789");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencontainers-runc' package(s) announced via the MGASA-2023-0125 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"/sys/fs/cgroup is writable when cgroupns isn't unshared (CVE-2023-25809)
Regression that reintroduced CVE-2019-19921 - Incorrect Access Control
leading to Escalation of Privileges (CVE-2023-27561)
AppArmor/SELinux bypass with symlinked /proc (CVE-2023-28642)");

  script_tag(name:"affected", value:"'opencontainers-runc' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"opencontainers-runc", rpm:"opencontainers-runc~1.1.5~1.mga8", rls:"MAGEIA8"))) {
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
