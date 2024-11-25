# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59016");
  script_cve_id("CVE-2007-3820", "CVE-2007-4224", "CVE-2007-4225", "CVE-2007-4569");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2007-264-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK12\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2007-264-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.455499");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20070919-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdebase' package(s) announced via the SSA:2007-264-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kdebase packages are available for Slackware 12.0 to fix security issues.

A long URL padded with spaces could be used to display a false URL in
Konqueror's addressbar, and KDM when used with no-password login could
be tricked into logging a different user in without a password. This
is not the way KDM is configured in Slackware by default, somewhat
mitigating the impact of this issue.

More details about the issues may be found here:

 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]


Here are the details from the Slackware 12.0 ChangeLog:
+--------------------------+
patches/packages/kdebase-3.5.7-i486-3_slack12.0.tgz:
 Patched Konqueror to prevent 'spoofing' the URL
 (i.e. displaying a URL other than the one associated with the page displayed)
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Patched KDM issue: 'KDM can be tricked into performing a password-less
 login even for accounts with a password set under certain circumstances,
 namely autologin to be configured and 'shutdown with password' enabled.'
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/kdelibs-3.5.7-i486-3_slack12.0.tgz:
 Patched Konqueror's supporting libraries to prevent addressbar spoofing.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kdebase' package(s) on Slackware 12.0.");

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

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"kdebase", ver:"3.5.7-i486-3_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kdelibs", ver:"3.5.7-i486-3_slack12.0", rls:"SLK12.0"))) {
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
