# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0937.1");
  script_cve_id("CVE-2021-27918", "CVE-2021-27919");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:41 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-18 14:34:45 +0000 (Thu, 18 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0937-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210937-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.16' package(s) announced via the SUSE-SU-2021:0937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.16 fixes the following issues:

go1.16.2 (released 2021-03-11) (bsc#1182345)

go1.16.1 (released 2021-03-10) (bsc#1182345)
 - CVE-2021-27918: Fixed an infinite loop when using xml.NewTokenDecoder
 with a custom TokenReader (bsc#1183333).
 - CVE-2021-27919: Fixed an issue where archive/zip: can panic when
 calling Reader.Open (bsc#1183334).");

  script_tag(name:"affected", value:"'go1.16' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"go1.16", rpm:"go1.16~1.16.2~1.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.16-doc", rpm:"go1.16-doc~1.16.2~1.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.16-race", rpm:"go1.16-race~1.16.2~1.8.1", rls:"SLES15.0SP2"))) {
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
