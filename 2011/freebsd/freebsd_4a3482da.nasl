# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68944");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560", "CVE-2011-0561", "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574", "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0607", "CVE-2011-0608");
  script_name("FreeBSD Ports: linux-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  linux-flashplugin
   linux-f8-flashplugin
   linux-f10-flashplugin

CVE-2011-0558
Integer overflow in Adobe Flash Player before 10.2.152.26 allows
attackers to execute arbitrary code via a large array length value in
the ActionScript method of the Function class.

CVE-2011-0559
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
crafted parameters to an unspecified ActionScript method that cause a
parameter to be used as an object pointer.

CVE-2011-0560
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0561
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0571
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0572
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0573
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0574
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0575
Untrusted search path vulnerability in Adobe Flash Player before
10.2.152.26 allows local users to gain privileges via a Trojan horse
DLL in the current working directory.

CVE-2011-0577
Unspecified vulnerability in Adobe Flash Player before 10.2.152.26
allows remote attackers to execute arbitrary code via a crafted font.

CVE-2011-0578
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors related to a constructor for an unspecified
ActionScript3 object and improper type checking.

CVE-2011-0607
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.

CVE-2011-0608
Adobe Flash Player before 10.2.152.26 allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-02.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4a3482da-3624-11e0-b995-001b2134ef46.html");

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

bver = portver(pkg:"linux-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"9.0r289")<=0) {
  txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f8-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.2r152")<0) {
  txt += 'Package linux-f8-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.2r152")<0) {
  txt += 'Package linux-f10-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}