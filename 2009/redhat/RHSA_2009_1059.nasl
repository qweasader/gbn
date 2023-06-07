# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:1059 ()
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
# or at your option, GNU General Public License version 3,
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
  script_oid("1.3.6.1.4.1.25623.1.0.64019");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
  script_cve_id("CVE-2009-1373", "CVE-2009-1376", "CVE-2008-2927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1059");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_3");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates to Pidgin announced in
advisory RHSA-2009:1059.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A buffer overflow flaw was found in the way Pidgin initiates file transfers
when using the Extensible Messaging and Presence Protocol (XMPP). If a
Pidgin client initiates a file transfer, and the remote target sends a
malformed response, it could cause Pidgin to crash or, potentially, execute
arbitrary code with the permissions of the user running Pidgin. This flaw
only affects accounts using XMPP, such as Jabber and Google Talk.
(CVE-2009-1373)

It was discovered that on 32-bit platforms, the Red Hat Security Advisory
RHSA-2008:0584 provided an incomplete fix for the integer overflow flaw
affecting Pidgin's MSN protocol handler. If a Pidgin client receives a
specially-crafted MSN message, it may be possible to execute arbitrary code
with the permissions of the user running Pidgin. (CVE-2009-1376)

Note: By default, when using an MSN account, only users on your buddy list
can send you messages. This prevents arbitrary MSN users from exploiting
this flaw.

All Pidgin users should upgrade to this update package, which contains
backported patches to resolve these issues. Pidgin must be restarted for
this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1059.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~1.5.1~3.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~1.5.1~3.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
