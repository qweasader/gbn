# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0093.1");
  script_cve_id("CVE-2022-40897");
  script_tag(name:"creation_date", value:"2023-01-18 04:20:27 +0000 (Wed, 18 Jan 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-06 18:34:00 +0000 (Fri, 06 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0093-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230093-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-setuptools' package(s) announced via the SUSE-SU-2023:0093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-setuptools fixes the following issues:

CVE-2022-40897: Fixed an excessive CPU usage that could be triggered by
 fetching a malicious HTML document (bsc#1206667).");

  script_tag(name:"affected", value:"'python-setuptools' package(s) on SUSE Linux Enterprise Module for Containers 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"python-setuptools", rpm:"python-setuptools~40.6.2~4.21.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-setuptools", rpm:"python3-setuptools~40.6.2~4.21.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python-setuptools", rpm:"python-setuptools~40.6.2~4.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-setuptools", rpm:"python3-setuptools~40.6.2~4.21.1", rls:"SLES12.0SP5"))) {
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
