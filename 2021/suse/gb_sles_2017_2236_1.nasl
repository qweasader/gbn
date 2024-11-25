# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2236.1");
  script_cve_id("CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-22 01:40:55 +0000 (Tue, 22 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2236-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172236-1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.3/static/release-9-3-18.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93' package(s) announced via the SUSE-SU-2017:2236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Postgresql93 was updated to 9.3.18 to fix the following issues:
* CVE-2017-7547: Further restrict visibility of
 pg_user_mappings.umoptions, to protect passwords stored as user mapping
 options. (bsc#1051685)
* CVE-2017-7546: Disallow empty passwords in all password-based
 authentication methods. (bsc#1051684)
* CVE-2017-7548: lo_put() function ignores ACLs. (bsc#1053259)
The changelog for the release is here:
 [link moved to references]");

  script_tag(name:"affected", value:"'postgresql93' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.18~25.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.18~25.5.1", rls:"SLES12.0"))) {
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
