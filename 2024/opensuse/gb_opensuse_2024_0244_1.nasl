# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856342");
  script_version("2024-08-21T05:05:38+0000");
  script_cve_id("CVE-2023-30549", "CVE-2023-38496", "CVE-2024-3727");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-21 05:05:38 +0000 (Wed, 21 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-05 16:43:37 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2024-08-17 04:00:25 +0000 (Sat, 17 Aug 2024)");
  script_name("openSUSE: Security Advisory for apptainer (openSUSE-SU-2024:0244-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0244-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3BEJQC6TDQZLJ4YE746IHLCFJFUQ2JKQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apptainer'
  package(s) announced via the openSUSE-SU-2024:0244-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apptainer fixes the following issues:

  - Make sure, digest values handled by the Go library
       github.com/opencontainers/go-digest and used throughout the
       Go-implemented containers ecosystem are always validated. This prevents
       attackers from triggering unexpected authenticated registry accesses.
       (CVE-2024-3727, boo#1224114).

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'apptainer' package(s) on openSUSE Backports SLE-15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsquashfuse0", rpm:"libsquashfuse0~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsquashfuse0-debuginfo", rpm:"libsquashfuse0-debuginfo~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse", rpm:"squashfuse~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-debuginfo", rpm:"squashfuse-debuginfo~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-debugsource", rpm:"squashfuse-debugsource~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-devel", rpm:"squashfuse-devel~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-tools", rpm:"squashfuse-tools~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-tools-debuginfo", rpm:"squashfuse-tools-debuginfo~0.5.0~bp155.2.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer", rpm:"apptainer~1.3.0~bp155.3.3.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-leap", rpm:"apptainer-leap~1.3.0~bp155.3.3.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_5", rpm:"apptainer-sle15_5~1.3.0~bp155.3.3.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_6", rpm:"apptainer-sle15_6~1.3.0~bp155.3.3.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
