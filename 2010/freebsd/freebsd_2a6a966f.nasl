# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66850");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-18 21:15:01 +0100 (Thu, 18 Feb 2010)");
  script_cve_id("CVE-2010-0562");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: fetchmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: fetchmail

CVE-2010-0562
The sdump function in sdump.c in fetchmail 6.3.11, 6.3.12, and 6.3.13,
when running in verbose mode on platforms for which char is signed,
allows remote attackers to cause a denial of service (application
crash) or possibly execute arbitrary code via an SSL X.509 certificate
containing non-printable characters with the high bit set, which
triggers a heap-based buffer overflow during escaping.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.fetchmail.info/fetchmail-SA-2010-01.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38088");
  script_xref(name:"URL", value:"https://lists.berlios.de/pipermail/fetchmail-announce/2010-February/000073.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2a6a966f-1774-11df-b5c1-0026189baca3.html");

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

bver = portver(pkg:"fetchmail");
if(!isnull(bver) && revcomp(a:bver, b:"6.3.11")>=0 && revcomp(a:bver, b:"6.3.14")<0) {
  txt += 'Package fetchmail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}