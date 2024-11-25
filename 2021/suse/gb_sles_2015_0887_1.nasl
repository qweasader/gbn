# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0887.1");
  script_cve_id("CVE-2013-4449", "CVE-2015-1545", "CVE-2015-1546");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0887-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0887-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150887-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap2' package(s) announced via the SUSE-SU-2015:0887-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"openldap2 was updated to fix three security issues and one non-security bug.
The following vulnerabilities were fixed:
A remote attacker could cause a denial of service (slapd crash) by unbinding immediately after a search request. (bnc#846389, CVE-2013-4449)
A remote attacker could cause a denial of service through a NULL pointer dereference and crash via an empty attribute list in a deref control in a search request. (bnc#916897, CVE-2015-1545)
A remote attacker could cause a denial of service (crash) via a crafted search query with a matched values control. (bnc#916914, CVE-2015-1546)
The following non-security bug was fixed:
Prevent connection-0 (internal connection) from showing up in the monitor back-end. (bnc#905959)
Security Issues:
CVE-2015-1546 CVE-2015-1545 CVE-2013-4449");

  script_tag(name:"affected", value:"'openldap2' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Security Module 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"compat-libldap-2_3-0", rpm:"compat-libldap-2_3-0~2.3.37~2.30.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.26~0.30.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.26~0.30.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-x86", rpm:"libldap-2_4-2-x86~2.4.26~0.30.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.26~0.30.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.26~0.30.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.26~0.30.1", rls:"SLES11.0SP3"))) {
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
