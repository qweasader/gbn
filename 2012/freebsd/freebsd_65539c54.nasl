# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72612");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-2687", "CVE-2012-0833");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
  script_name("FreeBSD Ports: apache22");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apache22
   apache22-event-mpm
   apache22-itk-mpm
   apache22-peruser-mpm
   apache22-worker-mpm

CVE-2012-2687
Multiple cross-site scripting (XSS) vulnerabilities in the
make_variant_list function in mod_negotiation.c in the mod_negotiation
module in the Apache HTTP Server 2.4.x before 2.4.3, when the
MultiViews option is enabled, allow remote attackers to inject
arbitrary web script or HTML via a crafted filename that is not
properly handled during construction of a variant list.
CVE-2012-0833
The acllas__handle_group_entry function in
servers/plugins/acl/acllas.c in 389 Directory Server before 1.2.10
does not properly handled access control instructions (ACIs) that use
certificate groups, which allows remote authenticated LDAP users with
a certificate group to cause a denial of service (infinite loop and
CPU consumption) by binding to the server.");

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

bver = portver(pkg:"apache22");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.23")<0) {
  txt += "Package apache22 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache22-event-mpm");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.23")<0) {
  txt += "Package apache22-event-mpm version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache22-itk-mpm");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.23")<0) {
  txt += "Package apache22-itk-mpm version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache22-peruser-mpm");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.23")<0) {
  txt += "Package apache22-peruser-mpm version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache22-worker-mpm");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.23")<0) {
  txt += "Package apache22-worker-mpm version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}