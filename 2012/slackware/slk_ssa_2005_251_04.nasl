# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55257");
  script_cve_id("CVE-2005-2491", "CVE-2005-2498");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2005-251-04)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK10\.1");

  script_xref(name:"Advisory-ID", value:"SSA:2005-251-04");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.417239");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the SSA:2005-251-04 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A new php5 package is available for Slackware 10.1 in /testing to fix
security issues. PHP has been relinked with the shared PCRE library
to fix an overflow issue with PHP's builtin PRCE code, and
PEAR::XMLRPC has been upgraded to version 1.4.0 which eliminates the
eval() function. The eval() function is believed to be insecure as
implemented, and would be difficult to secure.

Note that this new package now requires that the PCRE package be
installed, so be sure to get the new package from the patches/packages/
directory if you don't already have it.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]
 [link moved to references]

Here are the details from the Slackware 10.1 ChangeLog:
+--------------------------+
testing/packages/php-5.0.5/php-5.0.5-i486-1.tgz: Upgraded to
 php-5.0.5, which fixes security issues with XML-RPC and PCRE.
 This new package now links with the system's shared PCRE library,
 so be sure you have the new PCRE package from patches/packages/
 installed.
 Ordinarily packages in /testing are not considered supported, but
 several people have written to say that they are using php5 from
 /testing in a production environment and would like to see an
 updated package, so here it is. The package in /testing was
 replaced in /testing rather than putting it under /patches to
 avoid any problems with automatic upgrade tools replacing php-4
 packages with this one.
 For more information on the security issues fixed, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php5' package(s) on Slackware 10.1.");

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

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.0.5-i486-1", rls:"SLK10.1"))) {
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
