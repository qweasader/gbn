###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from ADV FreeBSD-SA-09:12.bind.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64490");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-0696");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-09:12.bind.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"BIND 9 is an implementation of the Domain Name System (DNS) protocols.
The named(8) daemon is an Internet Domain Name Server.

Dynamic update messages may be used to update records in a master zone
on a nameserver.

When named(8) receives a specially crafted dynamic update message an
internal assertion check is triggered which causes named(8) to exit.

To trigger the problem, the dynamic update message must contains a
record of type ANY and at least one resource record set (RRset) for
this fully qualified domain name (FQDN) must exist on the server.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:12.bind.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-09:12.bind.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"7.2", patchlevel:"3")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"7")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"12")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}