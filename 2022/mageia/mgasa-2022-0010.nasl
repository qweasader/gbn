# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0010");
  script_cve_id("CVE-2021-40153", "CVE-2021-41072");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 18:39:00 +0000 (Fri, 24 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0010");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0010.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29429");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5057-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RAOZ4BKWAC4Y3U2K5MMW3S77HWWXHQDL/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4967");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5078-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RGPPMRX4FP3CLIZKZFB2DODGNHXHPYD6/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4987");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5078-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squashfs-tools' package(s) announced via the MGASA-2022-0010 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"squashfs_opendir in unsquash-1.c in Squashfs-Tools 4.5 stores the filename
in the directory entry, this is then used by unsquashfs to create the new
file during the unsquash. The filename is not validated for traversal
outside of the destination directory, and thus allows writing to locations
outside of the destination. (CVE-2021-40153)
squashfs_opendir in unsquash-2.c in Squashfs-Tools 4.5 allows Directory
Traversal, a different vulnerability than CVE-2021-40153. A squashfs
filesystem that has been crafted to include a symbolic link and then
contents under the same filename in a filesystem can cause unsquashfs to
first create the symbolic link pointing outside the expected directory,
and then the subsequent write operation will cause the unsquashfs process
to write through the symbolic link elsewhere in the filesystem.
(CVE-2021-41072)");

  script_tag(name:"affected", value:"'squashfs-tools' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"squashfs-tools", rpm:"squashfs-tools~4.5~1.git5ae723.1.mga8", rls:"MAGEIA8"))) {
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
