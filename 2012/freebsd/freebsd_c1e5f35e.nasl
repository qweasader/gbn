# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71863");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-3479");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)");
  script_name("FreeBSD Ports: emacs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: emacs

CVE-2012-3479
lisp/files.el in Emacs 23.2, 23.3, 23.4, and 24.1 automatically
executes eval forms in local-variable sections when the
enable-local-variables option is set to :safe, which allows
user-assisted remote attackers to execute arbitrary Emacs Lisp code
via a crafted file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://lists.gnu.org/archive/html/emacs-devel/2012-08/msg00802.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54969");
  script_xref(name:"URL", value:"http://debbugs.gnu.org/cgi/bugreport.cgi?bug=12155");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c1e5f35e-f93d-11e1-b07f-00235a5f2c9a.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"emacs");
if(!isnull(bver) && revcomp(a:bver, b:"24.2")<0) {
  txt += "Package emacs version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}