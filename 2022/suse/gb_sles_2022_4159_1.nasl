# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4159.1");
  script_cve_id("CVE-2022-40617");
  script_tag(name:"creation_date", value:"2022-11-23 00:15:45 +0000 (Wed, 23 Nov 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-01 14:12:00 +0000 (Tue, 01 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4159-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224159-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the SUSE-SU-2022:4159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for strongswan fixes the following issues:

CVE-2022-40617: Fixed that using untrusted URIs for revocation checking
 could lead to denial of service (bsc#1203556)");

  script_tag(name:"affected", value:"'strongswan' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm", rpm:"strongswan-nm~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm-debuginfo", rpm:"strongswan-nm-debuginfo~5.8.2~150200.11.30.1", rls:"SLES15.0SP3"))) {
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
