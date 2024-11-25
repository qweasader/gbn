# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833027");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2023-2426", "CVE-2023-2609", "CVE-2023-2610");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-12 09:24:13 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:38:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for vim (SUSE-SU-2023:3497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3497-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TMRSMJVEQKPPUNPD37XKIRYR5LHGC5AC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the SUSE-SU-2023:3497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

  Updated to version 9.0 with patch level 1572.

  * CVE-2023-2426: Fixed Out-of-range Pointer Offset use (bsc#1210996).

  * CVE-2023-2609: Fixed NULL Pointer Dereference (bsc#1211256).

  * CVE-2023-2610: Fixed integer Overflow or Wraparound (bsc#1211257).");

  script_tag(name:"affected", value:"'vim' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.1632~150500.20.3.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.1632~150500.20.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.1632~150500.20.3.1##", rls:"openSUSELeap15.5"))) {
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
