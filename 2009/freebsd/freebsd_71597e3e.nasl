# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63358");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2008-5918", "CVE-2008-5919", "CVE-2009-0240");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: websvn");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: websvn

CVE-2008-5918
Cross-site scripting (XSS) vulnerability in the
getParameterisedSelfUrl function in index.php in WebSVN 2.0 and
earlier allows remote attackers to inject arbitrary web script or HTML
via the PATH_INFO.

CVE-2008-5919
Directory traversal vulnerability in rss.php in WebSVN 2.0 and
earlier, when magic_quotes_gpc is disabled, allows remote attackers to
overwrite arbitrary files via directory traversal sequences in the rev
parameter.

CVE-2009-0240
listing.php in WebSVN 2.0 and possibly 1.7 beta, when using an SVN
authz file, allows remote authenticated users to read changelogs or
diffs for restricted projects via a modified repname parameter.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32338/");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512191");
  script_xref(name:"URL", value:"http://www.gulftech.org/?node=research&article_id=00132-10202008");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/71597e3e-f6b8-11dd-94d9-0030843d3802.html");

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

bver = portver(pkg:"websvn");
if(!isnull(bver) && revcomp(a:bver, b:"2.1.0")<0) {
  txt += 'Package websvn version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}