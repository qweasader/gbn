# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3352.1");
  script_cve_id("CVE-2021-32785", "CVE-2021-32786", "CVE-2021-32791", "CVE-2021-32792", "CVE-2021-39191");
  script_tag(name:"creation_date", value:"2021-10-13 06:29:00 +0000 (Wed, 13 Oct 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-08 14:28:00 +0000 (Wed, 08 Sep 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3352-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3352-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213352-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_auth_openidc' package(s) announced via the SUSE-SU-2021:3352-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_auth_openidc fixes the following issues:

CVE-2021-32785: format string bug via hiredis (bsc#1188638)

CVE-2021-32786: open redirect in logout functionality (bsc#1188639)

CVE-2021-32791: Hardcoded static IV and AAD with a reused key in AES GCM
 encryption (bsc#1188849)

CVE-2021-32792: XSS when using OIDCPreservePost On (bsc#1188848)

CVE-2021-39191: open redirect issue in target_link_uri parameter
 (bsc#1190223)");

  script_tag(name:"affected", value:"'apache2-mod_auth_openidc' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc", rpm:"apache2-mod_auth_openidc~2.4.0~3.23.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc-debuginfo", rpm:"apache2-mod_auth_openidc-debuginfo~2.4.0~3.23.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc-debugsource", rpm:"apache2-mod_auth_openidc-debugsource~2.4.0~3.23.1", rls:"SLES12.0SP5"))) {
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
