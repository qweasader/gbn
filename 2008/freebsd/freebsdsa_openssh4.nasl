###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.60840");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-1483");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-08:05.openssh.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"OpenSSH is an implementation of the SSH protocol suite, providing an
encrypted and authenticated transport for a variety of services,
including remote shell access.  The OpenSSH server daemon (sshd)
provides support for the X11 protocol by binding to a port on the
server and forwarding any connections which are made to that port.

When logging in via SSH with X11-forwarding enabled, sshd(8) fails to
correctly handle the case where it fails to bind to an IPv4 port but
successfully binds to an IPv6 port.  In this case, applications which
use X11 will connect to the IPv4 port, even though it had not been
bound by sshd(8) and is therefore not being securely forwarded.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:05.openssh.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-08:05.openssh.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"7.1", patchlevel:"1")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"2")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.2", patchlevel:"12")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.1", patchlevel:"24")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.5", patchlevel:"20")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}