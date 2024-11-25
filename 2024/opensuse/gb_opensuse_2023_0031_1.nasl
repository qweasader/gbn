# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833680");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-23457");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 15:06:18 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:25:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for upx (openSUSE-SU-2023:0031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0031-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OY3PZTUNJBOAOSBB3625O5WLS7HRY73I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'upx'
  package(s) announced via the openSUSE-SU-2023:0031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"upx was updated to fix the following issues:

  - CVE-2023-23457: Fixed a segmentation fault when processing malicious elf
       files (boo#1207122)

     Update to release 4.0.1

  * Fix crash when a linux/armeb LZMA-packed binary unpacks itself.

  * Resolve 'CantPackException: bad ElfXX_Shdrs' with staticly-linked
       programs.

  * Resolve 'CantPackException: need DT_INIT ...' when attempting to
       re-compress an already packed binary.

     Update to release 4.0

  * Add support for EFI files");

  script_tag(name:"affected", value:"'upx' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"upx", rpm:"upx~4.0.1~bp154.4.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"upx", rpm:"upx~4.0.1~bp154.4.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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