# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57726");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: gzip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/11a84092-8f9f-11db-ab33-000e0c2e438a.html");
  script_tag(name:"insight", value:"The following package is affected: gzip

CVE-2006-4334
Unspecified vulnerability in gzip 1.3.5 allows context-dependent
attackers to cause a denial of service (crash) via a crafted GZIP (gz)
archive, which results in a NULL dereference.

CVE-2006-4335
Array index error in the make_table function in unlzh.c in the LZH
decompression component in gzip 1.3.5, when running on certain
platforms, allows context-dependent attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a crafted GZIP
archive that triggers an out-of-bounds write, aka a 'stack
modification vulnerability.'

CVE-2006-4336
Buffer underflow in the build_tree function in unpack.c in gzip 1.3.5 allows
context-dependent attackers to execute arbitrary code via a crafted leaf
count table that causes a write to a negative index.

CVE-2006-4337
Buffer overflow in the make_table function in the LHZ component in
gzip 1.3.5 allows context-dependent attackers to execute arbitrary
code via a crafted decoding table in a GZIP archive.

CVE-2006-4338
unlzh.c in the LHZ component in gzip 1.3.5 allows context-dependent
attackers to cause a denial of service (infinite loop) via a crafted
GZIP archive.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"gzip");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package gzip version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}