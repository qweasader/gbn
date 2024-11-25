# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0783.1");
  script_cve_id("CVE-2023-4750", "CVE-2023-48231", "CVE-2023-48232", "CVE-2023-48233", "CVE-2023-48234", "CVE-2023-48235", "CVE-2023-48236", "CVE-2023-48237", "CVE-2023-48706", "CVE-2024-22667");
  script_tag(name:"creation_date", value:"2024-03-07 04:31:50 +0000 (Thu, 07 Mar 2024)");
  script_version("2024-03-07T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-03-07 05:06:18 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 19:49:17 +0000 (Wed, 14 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0783-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0783-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240783-1/");
  script_xref(name:"URL", value:"https://github.com/vim/vim/compare/v9.0.2103...v9.1.0111");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2024:0783-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

CVE-2023-48231: Fixed Use-After-Free in win_close() (bsc#1217316).
CVE-2023-48232: Fixed Floating point Exception in adjust_plines_for_skipcol() (bsc#1217320).
CVE-2023-48233: Fixed overflow with count for :s command (bsc#1217321).
CVE-2023-48234: Fixed overflow in nv_z_get_count (bsc#1217324).
CVE-2023-48235: Fixed overflow in ex address parsing (bsc#1217326).
CVE-2023-48236: Fixed overflow in get_number (bsc#1217329).
CVE-2023-48237: Fixed overflow in shift_line (bsc#1217330).
CVE-2023-48706: Fixed heap-use-after-free in ex_substitute (bsc#1217432).
CVE-2024-22667: Fixed stack-based buffer overflow in did_set_langmap function in map.c (bsc#1219581).
CVE-2023-4750: Fixed heap use-after-free in function bt_quickfix (bsc#1215005).

Updated to version 9.1 with patch level 0111:
[link moved to references]");

  script_tag(name:"affected", value:"'vim' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.1.0111~17.29.1", rls:"SLES12.0SP5"))) {
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
