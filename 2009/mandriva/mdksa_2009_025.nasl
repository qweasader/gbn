# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:025 (pidgin)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63256");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-3532", "CVE-2008-2955", "CVE-2008-2957");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:025 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.1");
  script_tag(name:"insight", value:"The NSS plugin in libpurple in Pidgin 2.4.1 does not verify SSL
certificates, which makes it easier for remote attackers to trick
a user into accepting an invalid server certificate for a spoofed
service. (CVE-2008-3532)

Pidgin 2.4.1 allows remote attackers to cause a denial of service
(crash) via a long filename that contains certain characters, as
demonstrated using an MSN message that triggers the crash in the
msn_slplink_process_msg function. (CVE-2008-2955)

The UPnP functionality in Pidgin 2.0.0, and possibly other versions,
allows remote attackers to trigger the download of arbitrary files
and cause a denial of service (memory or disk consumption) via a UDP
packet that specifies an arbitrary URL. (CVE-2008-2957)

The updated packages have been patched to fix these issues.

Affected: 2008.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:025");
  script_tag(name:"summary", value:"The remote host is missing an update to pidgin
announced via advisory MDVSA-2009:025.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfinch0", rpm:"libfinch0~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple0", rpm:"libpurple0~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-bonjour", rpm:"pidgin-bonjour~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-client", rpm:"pidgin-client~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-gevolution", rpm:"pidgin-gevolution~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-i18n", rpm:"pidgin-i18n~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-meanwhile", rpm:"pidgin-meanwhile~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-mono", rpm:"pidgin-mono~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-silc", rpm:"pidgin-silc~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-tcl", rpm:"pidgin-tcl~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64finch0", rpm:"lib64finch0~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple0", rpm:"lib64purple0~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple-devel", rpm:"lib64purple-devel~2.4.1~2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
