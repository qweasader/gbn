# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13927.1");
  script_cve_id("CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20024", "CVE-2018-6307");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-07 21:11:03 +0000 (Mon, 07 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13927-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13927-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913927-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer' package(s) announced via the SUSE-SU-2019:13927-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibVNCServer fixes the following issues:

Security issues fixed:
CVE-2018-15126: Fixed use-after-free in file transfer extension
 (bsc#1120114)

CVE-2018-6307: Fixed use-after-free in file transfer extension server
 code (bsc#1120115)

CVE-2018-20020: Fixed heap out-of-bound write inside structure in VNC
 client code (bsc#1120116)

CVE-2018-15127: Fixed heap out-of-bounds write in rfbserver.c
 (bsc#1120117)

CVE-2018-20019: Fixed multiple heap out-of-bound writes in VNC client
 code (bsc#1120118)

CVE-2018-20022: Fixed information disclosure through improper
 initialization in VNC client code (bsc#1120120)

CVE-2018-20024: Fixed NULL pointer dereference in VNC client code
 (bsc#1120121)

CVE-2018-20021: Fixed infinite loop in VNC client code (bsc#1120122)");

  script_tag(name:"affected", value:"'LibVNCServer' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer", rpm:"LibVNCServer~0.9.1~160.6.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer", rpm:"LibVNCServer~0.9.1~160.6.1", rls:"SLES11.0SP4"))) {
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
