# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0046 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.63281");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
  script_cve_id("CVE-2009-0021");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Security Advisory RHSA-2009:0046");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0046.

The Network Time Protocol (NTP) is used to synchronize a computer's time
with a referenced time source.

A flaw was discovered in the way the ntpd daemon checked the return value
of the OpenSSL EVP_VerifyFinal function. On systems using NTPv4
authentication, this could lead to an incorrect verification of
cryptographic signatures, allowing time-spoofing attacks. (CVE-2009-0021)

Note: This issue only affects systems that have enabled NTP authentication.
By default, NTP authentication is not enabled.

All ntp users are advised to upgrade to the updated packages, which contain
a backported patch to resolve this issue. After installing the update, the
ntpd daemon will restart automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0046.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.0.a.20040617~8.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.0.a.20040617~8.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.2p1~9.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.2p1~9.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
