# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0020");
  script_cve_id("CVE-2021-45942");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-11 17:59:34 +0000 (Tue, 11 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0020");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0020.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29888");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QYJBECOXKL6LM6PP3ZL5EKF4GRPTFTD5/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-January/009997.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the MGASA-2022-0020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenEXR 3.1.0 through 3.1.3 has a heap-based buffer overflow in
Imf_3_1::LineCompositeTask::execute (called from
IlmThread_3_1::NullThreadPoolProvider::addTask and
IlmThread_3_1::ThreadPool::addGlobalTask). (CVE-2021-45942)");

  script_tag(name:"affected", value:"'openexr' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmbase-devel", rpm:"lib64ilmbase-devel~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmbase2_5_25", rpm:"lib64ilmbase2_5_25~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmimf2_5_25", rpm:"lib64ilmimf2_5_25~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openexr-devel", rpm:"lib64openexr-devel~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmbase-devel", rpm:"libilmbase-devel~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmbase2_5_25", rpm:"libilmbase2_5_25~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmimf2_5_25", rpm:"libilmimf2_5_25~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenexr-devel", rpm:"libopenexr-devel~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.5.7~1.3.mga8", rls:"MAGEIA8"))) {
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
