###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Notes Web Application XSS Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803216");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-4846");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-01-23 13:22:09 +0530 (Wed, 23 Jan 2013)");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("IBM Lotus Notes Web Application XSS Vulnerability (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51593");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56944");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027887");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79535");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21619604");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ibm_lotus_notes_detect_lin.nasl");
  script_mandatory_keys("IBM/LotusNotes/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.x before 8.5.3 FP3 on Linux");

  script_tag(name:"insight", value:"An error exists within the Web applications which allows an attacker to read
  or set the cookie value by injecting script.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Notes 8.5.3 FP3 or later.");

  script_tag(name:"summary", value:"IBM Lotus Notes is prone to a cross-site scripting (XSS) vulnerability.");

  exit(0);
}

include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/Linux/Ver");
if(!lotusVer){
  exit(0);
}

if(lotusVer =~ "^8\.5" &&
   version_is_less(version:lotusVer, test_version:"8.5.33")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
