# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0241");
  script_cve_id("CVE-2020-24119", "CVE-2021-20285");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-19 03:33:30 +0000 (Wed, 19 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0241");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0241.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29016");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/G3BQABK4YLXENDJBLDMHAIPRTC3ZMLYK/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VSQRO7YC72PSYDQG4PQLQYXZTZE3B4YV/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V2GCFGL5HHPU3GIC7XYIPIMYFFLH2M4U/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'upx' package(s) announced via the MGASA-2021-0241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package fixes security vulnerabilities:

A heap buffer overflow read was discovered in upx 4.0.0, because the
check in p_lx_elf.cpp is not perfect. (CVE-2020-24119)

A flaw was found in upx canPack in p_lx_elf.cpp in UPX 3.96. This flaw
allows attackers to cause a denial of service (SEGV or buffer overflow
and application crash) or possibly have unspecified other impacts via a
crafted ELF. The highest threat from this vulnerability is to system
availability. (CVE-2021-20285)");

  script_tag(name:"affected", value:"'upx' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"upx", rpm:"upx~3.96~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"upx", rpm:"upx~3.96~2.1.mga8", rls:"MAGEIA8"))) {
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
