# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0613.2");
  script_cve_id("CVE-2024-25062");
  script_tag(name:"creation_date", value:"2024-06-11 04:25:11 +0000 (Tue, 11 Jun 2024)");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 00:40:40 +0000 (Tue, 13 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0613-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0613-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240613-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2024:0613-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

CVE-2024-25062: Fixed use-after-free in XMLReader (bsc#1219576).");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit-debuginfo", rpm:"libxml2-2-32bit-debuginfo~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-debuginfo", rpm:"python3-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2", rpm:"python311-libxml2~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2-debuginfo", rpm:"python311-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"SLES15.0SP4"))) {
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
