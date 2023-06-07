###############################################################################
# OpenVAS Vulnerability Test
#
# GreenBrowser iframe Handling Double Free Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803067");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-6041");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-12-07 10:50:37 +0530 (Fri, 07 Dec 2012)");
  script_name("GreenBrowser iframe Handling Double Free Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47571");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51393");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72351");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-01/0079.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_greenbrowser_detect_win.nasl");
  script_mandatory_keys("GreenBrowser/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
code on the system or cause a denial of service.");
  script_tag(name:"affected", value:"GreenBrowser version 6.0.1002 and prior");
  script_tag(name:"insight", value:"A double free error exists in the shortcut button when handling
iframes, which can be exploited by tricking a user into opening a specially
crafted website.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"GreenBrowser is prone to double free vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

gbVer = get_kb_item("GreenBrowser/Win/Ver");

if(gbVer)
{
  if(version_is_less_equal(version:gbVer, test_version:"6.0.1002")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
