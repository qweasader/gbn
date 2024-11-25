# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53888");
  script_cve_id("CVE-2003-0282");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-237-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-237-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.357639");
  script_xref(name:"URL", value:"http://lwn.net/Articles/38540/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7550");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/12004");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the SSA:2003-237-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upgraded infozip packages are available for Slackware 9.0 and -current.
These fix a security issue where a specially crafted archive may
overwrite files (including system files anywhere on the filesystem)
upon extraction by a user with sufficient permissions.

For more information, see:

[link moved to references]
[link moved to references]
[link moved to references]
[link moved to references]


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Mon Aug 25 15:35:28 PDT 2003
patches/packages/infozip-5.50-i486-2.tgz: Fixed a bug where a specially
 crafted archive might try to write to ../ or ../../, etc, potentially
 overwriting system files if the user (such as root) has permissions to
 overwrite them. Thanks to jelmer for locating this problem, and
 Ben Laurie for providing a patch.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'unzip' package(s) on Slackware 9.0, Slackware current.");

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

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"infozip", ver:"5.50-i386-2", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"infozip", ver:"5.50-i486-2", rls:"SLKcurrent"))) {
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
