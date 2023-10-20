# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72459");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-5269", "CVE-2007-5503", "CVE-2007-5671", "CVE-2008-0967", "CVE-2008-1340", "CVE-2008-1361", "CVE-2008-1362", "CVE-2008-1363", "CVE-2008-1364", "CVE-2008-1392", "CVE-2008-1447", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2008-2098", "CVE-2008-2100", "CVE-2008-2101", "CVE-2008-4915", "CVE-2008-4916", "CVE-2008-4917", "CVE-2009-0040", "CVE-2009-0909", "CVE-2009-0910", "CVE-2009-1244", "CVE-2009-2267", "CVE-2009-3707", "CVE-2009-3732", "CVE-2009-3733", "CVE-2009-4811", "CVE-2010-1137", "CVE-2010-1138", "CVE-2010-1139", "CVE-2010-1140", "CVE-2010-1141", "CVE-2010-1142", "CVE-2010-1143", "CVE-2011-3868");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-03 11:11:29 -0400 (Wed, 03 Oct 2012)");
  script_name("Gentoo Security Advisory GLSA 201209-25 (vmware-server vmware-player vmware-workstation)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in VMware Player, Server,
and Workstation, allowing remote and local attackers to conduct several
attacks, including privilege escalation, remote execution of arbitrary
code, and a Denial of Service.");
  script_tag(name:"solution", value:"Gentoo discontinued support for VMware Player. We recommend that users
unmerge VMware Player:

      # emerge --unmerge 'app-emulation/vmware-player'


NOTE: Users could upgrade to > =app-emulation/vmware-player-3.1.5,
however these packages are not currently stable.

Gentoo discontinued support for VMware Workstation. We recommend that
users unmerge VMware Workstation:

      # emerge --unmerge 'app-emulation/vmware-workstation'


NOTE: Users could upgrade to > =app-emulation/vmware-workstation-7.1.5,
however these packages are not currently stable.

Gentoo discontinued support for VMware Server. We recommend that users
  unmerge VMware Server:

      # emerge --unmerge 'app-emulation/vmware-server'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-25");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=213548");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=224637");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=236167");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=245941");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=265139");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=282213");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=297367");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=335866");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=385727");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201209-25.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-emulation/vmware-player", unaffected: make_list(), vulnerable: make_list("le 2.5.5.328052"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"app-emulation/vmware-workstation", unaffected: make_list(), vulnerable: make_list("le 6.5.5.328052"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"app-emulation/vmware-server", unaffected: make_list(), vulnerable: make_list("le 1.0.9.156507"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
