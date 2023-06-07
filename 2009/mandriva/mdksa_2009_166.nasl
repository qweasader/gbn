# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:166 (c-client)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64499");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2008-5005", "CVE-2008-5006", "CVE-2008-5514");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:166 (c-client)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"insight", value:"Security vulnerabilities has been identified and fixed in University
of Washington IMAP Toolkit:

Multiple stack-based buffer overflows in (1) University of Washington
IMAP Toolkit 2002 through 2007c, (2) University of Washington Alpine
2.00 and earlier, and (3) Panda IMAP allow (a) local users to gain
privileges by specifying a long folder extension argument on the
command line to the tmail or dmail program, and (b) remote attackers to
execute arbitrary code by sending e-mail to a destination mailbox name
composed of a username and '+' character followed by a long string,
processed by the tmail or possibly dmail program (CVE-2008-5005).

smtp.c in the c-client library in University of Washington IMAP Toolkit
2007b allows remote SMTP servers to cause a denial of service (NULL
pointer dereference and application crash) by responding to the QUIT
command with a close of the TCP connection instead of the expected
221 response code (CVE-2008-5006).

Off-by-one error in the rfc822_output_char function in the RFC822BUFFER
routines in the University of Washington (UW) c-client library, as
used by the UW IMAP toolkit before imap-2007e and other applications,
allows context-dependent attackers to cause a denial of service (crash)
via an e-mail message that triggers a buffer overflow (CVE-2008-5514).

The updated packages have been patched to prevent this. Note that the
software was renamed to c-client starting from Mandriva Linux 2009.0
and only provides the shared c-client library for the imap functions
in PHP.

Affected: Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:166");
  script_tag(name:"summary", value:"The remote host is missing an update to c-client
announced via advisory MDVSA-2009:166.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libc-client0", rpm:"libc-client0~2007b~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libc-client-devel", rpm:"libc-client-devel~2007b~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64c-client0", rpm:"lib64c-client0~2007b~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64c-client-devel", rpm:"lib64c-client-devel~2007b~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
