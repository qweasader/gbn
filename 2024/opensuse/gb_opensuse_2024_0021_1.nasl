# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833285");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-22368");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 14:58:04 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for perl (openSUSE-SU-2024:0021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0021");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EHHPL7IKGNQCRM3NOTRZRDYWT4OKW47L");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-Spreadsheet-ParseXLSX fixes the following issues:

  - Fix die message in parse()

  - Cannot open password protected SHA1 encrypted files. doy#68

  - use date format detection based on Spreadsheet::XLSX

  - Add rudimentary support for hyperlinks in cells

     0.28:

  - CVE-2024-22368: out-of-memory condition during parsing of a crafted XLSX
       document (boo#1218651)

  - Fix possible memory bomb as reported in
       lsx_bomb.md

  - Updated Dist::Zilla configuration fixing deprecation warnings");

  script_tag(name:"affected", value:"'perl' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Spreadsheet-ParseXLSX", rpm:"perl-Spreadsheet-ParseXLSX~0.290.0~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
