# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0205 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.63248");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-4577", "CVE-2008-4870");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("RedHat Security Advisory RHSA-2009:0205");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates to Dovecot announced in
advisory RHSA-2009:0205.

A flaw was found in Dovecot's ACL plug-in. The ACL plug-in treated negative
access rights as positive rights, which could allow an attacker to bypass
intended access restrictions. (CVE-2008-4577)

A password disclosure flaw was found with Dovecot's configuration file. If
a system had the ssl_key_password option defined, any local user could
view the SSL key password. (CVE-2008-4870)

Note: This flaw did not allow the attacker to acquire the contents of the
SSL key. The password has no value without the key file which arbitrary
users should not have read access to.

To better protect even this value, however, the dovecot.conf file now
supports the !include_try directive. The ssl_key_password option should
be moved from dovecot.conf to a new file owned by, and only readable and
writable by, root (ie 0600). This file should be referenced from
dovecot.conf by setting the !include_try [/path/to/password/file] option.

Additionally, a number of bug fixes were made (see the referenced
advisories for details).

Users of dovecot are advised to upgrade to this updated package, which
addresses these vulnerabilities and resolves these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0205.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#low");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.0.7~7.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-debuginfo", rpm:"dovecot-debuginfo~1.0.7~7.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
