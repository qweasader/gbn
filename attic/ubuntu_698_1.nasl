###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory USN-698-1 (nagios)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64163");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2008-5027", "CVE-2008-5302", "CVE-2008-5303", "CVE-2008-2435", "CVE-2008-1102", "CVE-2008-4863", "CVE-2008-5028", "CVE-2007-3555", "CVE-2008-1502", "CVE-2008-3325", "CVE-2008-3326", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811", "CVE-2008-5432", "CVE-2008-5619", "CVE-2008-2426", "CVE-2008-2434", "CVE-2008-4242", "CVE-2007-3372", "CVE-2008-5081", "CVE-2008-4577", "CVE-2008-4870", "CVE-2008-5140", "CVE-2008-5312", "CVE-2008-5313", "CVE-2008-4844", "CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu USN-698-1 (nagios)");
  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-698-1/");
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Ubuntu Local Security Checks");

  script_tag(name:"insight", value:"It was discovered that Nagios did not properly parse commands submitted using
the web interface. An authenticated user could use a custom form or a browser
addon to bypass security restrictions and submit unauthorized commands.");
  script_tag(name:"summary", value:"The remote host is missing an update to nagios
announced via advisory USN-698-1.");
  script_tag(name:"solution", value:"The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  nagios-common                   2:1.3-cvs.20050402-8ubuntu8

After a standard system upgrade you need to restart Nagios to effect
the necessary changes.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
