# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2017.251.01");
  script_cve_id("CVE-2016-0634", "CVE-2016-7543");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-20 16:32:29 +0000 (Fri, 20 Jan 2017)");

  script_name("Slackware: Security Advisory (SSA:2017-251-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.1|13\.37|14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2017-251-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.503015");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash' package(s) announced via the SSA:2017-251-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New bash packages are available for Slackware 13.1, 13.37, 14.0, 14.1, and 14.2
to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/bash-4.3.048-i586-1_slack14.2.txz: Upgraded.
 This update fixes two security issues found in bash before 4.4:
 The expansion of '\h' in the prompt string allows remote authenticated users
 to execute arbitrary code via shell metacharacters placed in 'hostname' of a
 machine. The theoretical attack vector is a hostile DHCP server providing a
 crafted hostname, but this is unlikely to occur in a normal Slackware
 configuration as we ignore the hostname provided by DHCP.
 Specially crafted SHELLOPTS+PS4 environment variables used against bogus
 setuid binaries using system()/popen() allowed local attackers to execute
 arbitrary code as root.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'bash' package(s) on Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware 14.2.");

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

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.1.017-i486-2_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.1.017-x86_64-2_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.37") {

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.1.017-i486-2_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.1.017-x86_64-2_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.2.053-i486-2_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.2.053-x86_64-2_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.2.053-i486-2_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.2.053-x86_64-2_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.3.048-i586-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bash", ver:"4.3.048-x86_64-1_slack14.2", rls:"SLK14.2"))) {
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
