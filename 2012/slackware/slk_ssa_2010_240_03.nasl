# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68174");
  script_cve_id("CVE-2010-2575");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2010-240-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK13\.1");

  script_xref(name:"Advisory-ID", value:"SSA:2010-240-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.340142");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20100825-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdegraphics' package(s) announced via the SSA:2010-240-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kdegraphics packages are available for Slackware 13.1 to
fix a security issue in the okular document viewer.

Here are the details from the Slackware 13.1 ChangeLog:
+--------------------------+
patches/packages/kdegraphics-4.4.3-i486-3_slack13.1.txz: Rebuilt.
 Patched 'Okular PDB Processing Memory Corruption Vulnerability'
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kdegraphics' package(s) on Slackware 13.1.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"kdegraphics", ver:"4.4.3-i486-3_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kdegraphics", ver:"4.4.3-x86_64-3_slack13.1", rls:"SLK13.1"))) {
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
