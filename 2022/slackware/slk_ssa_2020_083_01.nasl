# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2020.083.01");
  script_cve_id("CVE-2018-1000222", "CVE-2018-14553", "CVE-2018-5711", "CVE-2019-11038", "CVE-2019-6977", "CVE-2019-6978");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-29 13:39:24 +0000 (Tue, 29 Jan 2019)");

  script_name("Slackware: Security Advisory (SSA:2020-083-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2020-083-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2020&m=slackware-security.379791");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gd' package(s) announced via the SSA:2020-083-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gd packages are available for Slackware 14.2 and -current to
fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/gd-2.3.0-i586-1_slack14.2.txz: Upgraded.
 This update fixes bugs and security issues:
 Potential double-free in gdImage*Ptr().
 gdImageColorMatch() out of bounds write on heap.
 Uninitialized read in gdImageCreateFromXbm().
 Double-free in gdImageBmp.
 Potential NULL pointer dereference in gdImageClone().
 Potential infinite loop in gdImageCreateFromGifCtx().
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gd' package(s) on Slackware 14.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"gd", ver:"2.3.0-i586-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gd", ver:"2.3.0-x86_64-1_slack14.2", rls:"SLK14.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gd", ver:"2.3.0-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gd", ver:"2.3.0-x86_64-1", rls:"SLKcurrent"))) {
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
