# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68688");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4207", "CVE-2010-4208", "CVE-2010-4209");
  script_name("FreeBSD Ports: yahoo-ui");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: yahoo-ui

CVE-2010-4207
Cross-site scripting (XSS) vulnerability in the Flash component
infrastructure in YUI 2.4.0 through 2.8.1, as used in Bugzilla,
Moodle, and other products, allows remote attackers to inject
arbitrary web script or HTML via vectors related to
charts/assets/charts.swf.

CVE-2010-4208
Cross-site scripting (XSS) vulnerability in the Flash component
infrastructure in YUI 2.5.0 through 2.8.1, as used in Bugzilla,
Moodle, and other products, allows remote attackers to inject
arbitrary web script or HTML via vectors related to
uploader/assets/uploader.swf.

CVE-2010-4209
Cross-site scripting (XSS) vulnerability in the Flash component
infrastructure in YUI 2.8.0 through 2.8.1, as used in Bugzilla 3.7.1
through 3.7.3 and 4.1, allows remote attackers to inject arbitrary web
script or HTML via vectors related to swfstore/swfstore.swf.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.yuiblog.com/blog/2010/10/25/yui-2-8-2-security-update/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41955");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/11/07/1");
  script_xref(name:"URL", value:"http://yuilibrary.com/support/2.8.2/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/d560b346-08a2-11e0-bcca-0050568452ac.html");

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

bver = portver(pkg:"yahoo-ui");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.2")<0) {
  txt += 'Package yahoo-ui version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}