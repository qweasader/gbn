# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70591");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_cve_id("CVE-2011-1530");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_version("2023-07-26T05:05:09+0000");
  script_name("FreeBSD Ports: krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: krb5

CVE-2011-1530
The process_tgs_req function in do_tgs_req.c in the Key Distribution
Center (KDC) in MIT Kerberos 5 (aka krb5) 1.9 through 1.9.2 allows
remote authenticated users to cause a denial of service (NULL pointer
dereference and daemon crash) via a crafted TGS request that triggers
an error other than the KRB5_KDB_NOENTRY error.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2011-007.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6c7d9a35-2608-11e1-89b4-001ec9578670.html");

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

bver = portver(pkg:"krb5");
if(!isnull(bver) && revcomp(a:bver, b:"1.9")>=0 && revcomp(a:bver, b:"1.9.2_1")<0) {
  txt += 'Package krb5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}