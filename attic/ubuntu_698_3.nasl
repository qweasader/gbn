###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory USN-698-3 (nagios2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64164");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2008-5027", "CVE-2008-5028", "CVE-2007-2739", "CVE-2008-5033", "CVE-2008-4933", "CVE-2008-5025", "CVE-2007-2865", "CVE-2007-5728", "CVE-2008-5587", "CVE-2008-2383", "CVE-2008-3443", "CVE-2008-5029", "CVE-2009-0022", "CVE-2006-7236", "CVE-2008-2382");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu USN-698-3 (nagios2)");
  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-698-3/");
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Ubuntu Local Security Checks");

  script_tag(name:"insight", value:"It was discovered that Nagios was vulnerable to a Cross-site request forgery
(CSRF) vulnerability. If an authenticated nagios user were tricked into
clicking a link on a specially crafted web page, an attacker could trigger
commands to be processed by Nagios and execute arbitrary programs. This
update alters Nagios behaviour by disabling submission of CMD_CHANGE commands.
(CVE-2008-5028)

It was discovered that Nagios did not properly parse commands submitted using
the web interface. An authenticated user could use a custom form or a browser
addon to bypass security restrictions and submit unauthorized commands.
(CVE-2008-5027)");
  script_tag(name:"summary", value:"The remote host is missing an update to nagios2
announced via advisory USN-698-3.");
  script_tag(name:"solution", value:"The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 8.04 LTS:
  nagios2                         2.11-1ubuntu1.4

After a standard system upgrade you need to restart Nagios to effect
the necessary changes.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
