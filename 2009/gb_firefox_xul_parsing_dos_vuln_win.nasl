###############################################################################
# OpenVAS Vulnerability Test
#
# Firefox XUL Parsing Denial of Service Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800389");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1232");
  script_name("Firefox XUL Parsing Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8306");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49521");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause the browser to crash.");
  script_tag(name:"affected", value:"Firefox version 3.0 to 3.0.8 on Windows.");
  script_tag(name:"insight", value:"Error in browser due to improper parsing of XUL (XML) documents while opening
  a specially-crafted XML document containing long series of start-tags with no
  corresponding end-tags.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to XUL Parsing Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(!vers)
  exit(0);

if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.0.8")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"3.0 - 3.0.8");
  security_message(port: 0, data: report);
}
