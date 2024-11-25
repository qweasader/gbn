# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3768.1");
  script_cve_id("CVE-2018-15473", "CVE-2018-15919");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:34 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 16:04:30 +0000 (Wed, 07 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3768-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3768-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183768-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh-openssl1' package(s) announced via the SUSE-SU-2018:3768-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh-openssl1 fixes the following issues:

Security issues fixed:
CVE-2018-15919: Remotely observable behaviour in auth-gss2.c in OpenSSH
 could be used by remote attackers to detect existence of users on a
 target system when GSS2 is in use. OpenSSH developers do not want to
 treat such a username enumeration (or 'oracle') as a vulnerability.
 (bsc#1106163)

CVE-2018-15473: OpenSSH was prone to a user existance oracle
 vulnerability due to not delaying bailout for an invalid authenticating
 user until after the packet containing the request has been fully
 parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
 (bsc#1105010)

Following non-security issues were fixed:
Fix for sftp client because it returns wrong error code upon failure
 (bsc#1091396)

Stop leaking File descriptors (bsc#964336)");

  script_tag(name:"affected", value:"'openssh-openssl1' package(s) on SUSE Linux Enterprise Server 11.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"openssh-openssl1", rpm:"openssh-openssl1~6.6p1~19.6.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-openssl1-helpers", rpm:"openssh-openssl1-helpers~6.6p1~19.6.1", rls:"SLES11.0"))) {
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
