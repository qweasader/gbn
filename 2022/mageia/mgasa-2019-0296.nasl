# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0296");
  script_cve_id("CVE-2019-5094");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-25 15:40:34 +0000 (Wed, 25 Sep 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0296)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0296");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0296.html");
  script_xref(name:"URL", value:"http://e2fsprogs.sourceforge.net/e2fsprogs-release.html#1.45.4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25562");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4535");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'e2fsprogs' package(s) announced via the MGASA-2019-0296 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated e2fsprogs packages fix security vulnerability:

Lilith of Cisco Talos discovered a buffer overflow flaw in the quota code
used by e2fsck from the ext2/ext3/ext4 file system utilities. Running
e2fsck on a malformed file system can result in the execution of arbitrary
code (CVE-2019-5094).

The e2fsprogs package has been updated to version 1.45.4, fixing this issue
and other bugs. See the upstream release notes for details.");

  script_tag(name:"affected", value:"'e2fsprogs' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs", rpm:"e2fsprogs~1.45.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ext2fs-devel", rpm:"lib64ext2fs-devel~1.45.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ext2fs2", rpm:"lib64ext2fs2~1.45.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs-devel", rpm:"libext2fs-devel~1.45.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2", rpm:"libext2fs2~1.45.4~1.mga7", rls:"MAGEIA7"))) {
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
