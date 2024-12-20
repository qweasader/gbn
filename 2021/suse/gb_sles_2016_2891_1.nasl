# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2891.1");
  script_cve_id("CVE-2016-7032", "CVE-2016-7076");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-09 14:21:14 +0000 (Mon, 09 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2891-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162891-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2016:2891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sudo fixes the following issues:
- Fix two security vulnerabilities that allowed users to bypass sudo's
 NOEXEC functionality:
 * noexec bypass via system() and popen() [CVE-2016-7032, bsc#1007766]
 * noexec bypass via wordexp() [CVE-2016-7076, bsc#1007501]
- The SSSD plugin would occasionally crash sudo with an 'internal error'.
 This issue has been fixed. [bsc#948973]
- The SSSD plugin would occasionally apply @netgroups rules from LDAP to
 all users rather than the @netgroup. This issue is now fixed.
 [bsc#966755]
- When the SSSD plugin was used and a local user ran sudo, an e-mail used
 to be sent to administrator because SSSD did not support sudo rules for
 local users. This message did not signify an error, however, it was only
 noise. [bsc#1008043]");

  script_tag(name:"affected", value:"'sudo' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.6p2~0.29.1", rls:"SLES11.0SP4"))) {
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
