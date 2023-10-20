# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0117.1");
  script_cve_id("CVE-2011-3919");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:29 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120117-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2012:0117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow during decoding of entity references with overly long names has been fixed.
CVE-2011-3919 has been assigned.

Security Issue reference:

 * CVE-2011-3919
>");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Software Development Kit 11-SP1.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-32bit", rpm:"libxml2-32bit~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-64bit", rpm:"libxml2-64bit~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-64bit", rpm:"libxml2-devel-64bit~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-x86", rpm:"libxml2-x86~2.6.23~15.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~0.13.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-32bit", rpm:"libxml2-32bit~2.7.6~0.13.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.7.6~0.13.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-x86", rpm:"libxml2-x86~2.7.6~0.13.1", rls:"SLES11.0SP1"))) {
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
