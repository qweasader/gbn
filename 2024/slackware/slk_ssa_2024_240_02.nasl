# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.240.02");
  script_cve_id("CVE-2024-36041");
  script_tag(name:"creation_date", value:"2024-08-28 04:09:59 +0000 (Wed, 28 Aug 2024)");
  script_version("2024-08-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-08-28 05:05:33 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 16:46:20 +0000 (Mon, 08 Jul 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-240-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2024-240-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.319600");
  script_xref(name:"URL", value:"https://kde.org/info/security/advisory-20240531-1.txt");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-36041");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'plasma-workspace' package(s) announced via the SSA:2024-240-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New plasma-workspace packages are available for Slackware 15.0 to fix
a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/plasma-workspace-5.23.5-i586-4_slack15.0.txz: Rebuilt.
 This update patches a security issue:
 ksmserver: Unauthorized users can access session manager.
 Thanks to pbslxw for the heads-up.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'plasma-workspace' package(s) on Slackware 15.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"plasma-workspace", ver:"5.23.5-i586-4_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"plasma-workspace", ver:"5.23.5-x86_64-4_slack15.0", rls:"SLK15.0"))) {
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
