###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Informix Dynamic Server 'oninit.exe' Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802292");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2010-4053");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-01-12 17:17:17 +0530 (Thu, 12 Jan 2012)");
  script_name("IBM Informix Dynamic Server 'oninit.exe' Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41913");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44192");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62619");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-216");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_informix_dynamic_server_detect_win.nasl");
  script_mandatory_keys("IBM/Informix/Dynamic/Server/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.");
  script_tag(name:"affected", value:"IBM Informix Dynamic Server (IDS) 11.10 before 11.10.xC2W2 and 11.50 before 11.50.xC1");
  script_tag(name:"insight", value:"The flaw is due to a boundary error within the logging function in
  oninit.exe and can be exploited to cause a stack-based buffer overflow by
  sending a specially crafted request to TCP ports 9088 or 1526.");
  script_tag(name:"solution", value:"Upgrade to IBM Informix IDS version 11.50.xC1, 11.10.xC2W2 or later.");
  script_tag(name:"summary", value:"IBM Informix Dynamic Server is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("IBM/Informix/Dynamic/Server/Win/Ver");
if(version)
{
  if(version_is_equal(version:version, test_version:"11.10") ||
     version_is_equal(version:version, test_version:"11.50")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
