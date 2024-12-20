# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1777.1");
  script_cve_id("CVE-2015-4680", "CVE-2017-9148");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-09 16:22:00 +0000 (Fri, 09 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1777-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171777-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius-server' package(s) announced via the SUSE-SU-2017:1777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freeradius-server fixes the following issues:
- CVE-2017-9148: Disable OpenSSL's internal session cache to mitigate
 authentication bypass. (bnc#1041445)
- CVE-2015-4680: Add a configuration option to allow checking of all
 intermediate certificates for revocations. (bnc#935573)
The following non security issue was fixed:
- Cannot create table radpostauth because of deprecated TIMESTAMP(14)
 syntax. (bsc#912873)");

  script_tag(name:"affected", value:"'freeradius-server' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~2.1.1~7.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-dialupadmin", rpm:"freeradius-server-dialupadmin~2.1.1~7.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~2.1.1~7.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~2.1.1~7.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~2.1.1~7.24.1", rls:"SLES11.0SP4"))) {
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
