# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.347.01");
  script_cve_id("CVE-2023-6377", "CVE-2023-6478");
  script_tag(name:"creation_date", value:"2023-12-14 04:21:10 +0000 (Thu, 14 Dec 2023)");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:18:00 +0000 (Thu, 21 Dec 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-347-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-347-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.676193");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg/2023-December/061517.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-6377");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-6478");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server' package(s) announced via the SSA:2023-347-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xorg-server packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/xorg-server-1.20.14-i586-10_slack15.0.txz: Rebuilt.
 This update fixes two security issues:
 Out-of-bounds memory write in XKB button actions.
 Out-of-bounds memory read in RRChangeOutputProperty and
 RRChangeProviderProperty.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/xorg-server-xephyr-1.20.14-i586-10_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xnest-1.20.14-i586-10_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xvfb-1.20.14-i586-10_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xwayland-21.1.4-i586-9_slack15.0.txz: Rebuilt.
 This update fixes two security issues:
 Out-of-bounds memory write in XKB button actions.
 Out-of-bounds memory read in RRChangeOutputProperty and
 RRChangeProviderProperty.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Slackware 15.0, Slackware current.");

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

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.20.14-i586-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.20.14-x86_64-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.20.14-i586-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.20.14-x86_64-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.20.14-i586-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.20.14-x86_64-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.20.14-i586-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.20.14-x86_64-10_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"21.1.4-i586-9_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"21.1.4-x86_64-9_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"21.1.10-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"21.1.10-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"21.1.10-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"21.1.10-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"21.1.10-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"21.1.10-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"21.1.10-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"21.1.10-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"23.2.3-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"23.2.3-x86_64-1", rls:"SLKcurrent"))) {
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
