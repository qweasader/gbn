###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from ADV FreeBSD-SA-10:05.opie.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2010 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.67506");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1938");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-10:05.opie.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"OPIE is a one-time password system designed to help to secure a system
against replay attacks.  It does so using a secure hash function and a
challenge/response system.

OPIE is enabled by default on FreeBSD.

A programming error in the OPIE library could allow an off-by-one buffer
overflow to write a single zero byte beyond the end of an on-stack buffer.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:05.opie.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-10:05.opie.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"8.0", patchlevel:"3")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"1")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.2", patchlevel:"8")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"12")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"10")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}