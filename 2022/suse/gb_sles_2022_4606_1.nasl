# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4606.1");
  script_cve_id("CVE-2021-21272", "CVE-2022-1996", "CVE-2022-23524", "CVE-2022-23525", "CVE-2022-23526");
  script_tag(name:"creation_date", value:"2022-12-23 04:18:17 +0000 (Fri, 23 Dec 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4606-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4606-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224606-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'helm' package(s) announced via the SUSE-SU-2022:4606-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for helm fixes the following issues:

Update to version 3.10.3:

CVE-2022-23524: Fixed a denial of service in the string value parsing
 (bsc#1206467).

CVE-2022-23525: Fixed a denial of service with the repository index file
 (bsc#1206469).

CVE-2022-23526: Fixed a denial of service in the schema file handling
 (bsc#1206471).");

  script_tag(name:"affected", value:"'helm' package(s) on SUSE Linux Enterprise Module for Containers 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"helm", rpm:"helm~3.10.3~150000.1.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-bash-completion", rpm:"helm-bash-completion~3.10.3~150000.1.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-debuginfo", rpm:"helm-debuginfo~3.10.3~150000.1.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-zsh-completion", rpm:"helm-zsh-completion~3.10.3~150000.1.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-fish-completion", rpm:"helm-fish-completion~3.10.3~150000.1.13.1", rls:"SLES15.0SP4"))) {
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
