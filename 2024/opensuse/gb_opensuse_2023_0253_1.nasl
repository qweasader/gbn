# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833160");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-33863", "CVE-2023-33864", "CVE-2023-33865");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-14 19:48:06 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:25:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for renderdoc (openSUSE-SU-2023:0253-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0253-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OUXFQKIACDXNDNRMXVBF6QD6SJQYGXBM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'renderdoc'
  package(s) announced via the openSUSE-SU-2023:0253-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for renderdoc fixes the following issues:

     Security issues fixed:

  * CVE-2023-33863: integer overflow to heap-based buffer overflow

  * CVE-2023-33864: integer underflow to heap-based buffer overflow

  * CVE-2023-33865: symlink vulnerability in /tmp/RenderDoc");

  script_tag(name:"affected", value:"'renderdoc' package(s) on openSUSE Backports SLE-15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"renderdoc", rpm:"renderdoc~1.24~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"renderdoc-devel", rpm:"renderdoc-devel~1.24~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"renderdoc", rpm:"renderdoc~1.24~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"renderdoc-devel", rpm:"renderdoc-devel~1.24~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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