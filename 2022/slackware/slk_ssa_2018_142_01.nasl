# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2018.142.01");
  script_cve_id("CVE-2018-1000004", "CVE-2018-1092");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-02 14:21:53 +0000 (Wed, 02 May 2018)");

  script_name("Slackware: Security Advisory (SSA:2018-142-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2018-142-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2018&m=slackware-security.696300");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2018-142-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 14.2 to fix a regression in the
getsockopt() function and to fix two denial-of-service security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/linux-4.4.132/*: Upgraded.
 This kernel upgrade is being provided primarily to fix a regression in the
 getsockopt() function, but it also contains fixes for two denial-of-service
 security issues.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 14.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"20180518_2a9b2cf-noarch-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.132-i586-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.132-x86_64-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"4.4.132_smp-i686-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.132-x86-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.132_smp-x86-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.132-i586-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.132-x86_64-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"4.4.132_smp-i686-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.132-i586-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.132-x86_64-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"4.4.132_smp-i686-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.132-noarch-1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.132_smp-noarch-1", rls:"SLK14.2"))) {
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
