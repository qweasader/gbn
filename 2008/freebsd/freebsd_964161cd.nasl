# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55969");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2005-4048", "CVE-2006-4799", "CVE-2006-4800");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: ffmpeg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected: ffmpeg ffmpeg-devel");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://article.gmane.org/gmane.comp.video.ffmpeg.devel/26558");
  script_xref(name:"URL", value:"http://secunia.com/advisories/17892/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/964161cd-6715-11da-99f6-00123ffe8333.html");

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

bver = portver(pkg:"ffmpeg");
if(!isnull(bver) && revcomp(a:bver, b:"0.4.9.p1_4")<0) {
  txt += 'Package ffmpeg version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ffmpeg-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0.4.9.c.2005120600")<0) {
  txt += 'Package ffmpeg-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}