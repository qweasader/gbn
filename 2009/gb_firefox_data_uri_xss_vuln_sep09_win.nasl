###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox 'data:' URI XSS Vulnerability - Sep09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800889");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3012");
  script_name("Mozilla Firefox 'data:' URI XSS Vulnerability - Sep09 (Windows)");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3323/");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.");
  script_tag(name:"affected", value:"Mozilla, Firefox version 3.0.13 and prior, 3.5 and 3.6/3.7 a1 pre on Windows.");
  script_tag(name:"insight", value:"Firefox fails to sanitise the 'data:' URIs in Location headers in HTTP
  responses, which can be exploited via vectors related to injecting a
  Location header or Location HTTP response header.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Product(s) is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");

if(ffVer)
{
  if(version_is_less_equal(version:ffVer, test_version:"3.0.13")||
     version_is_equal(version:ffVer, test_version:"3.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
else if(registry_key_exists(key:"SOFTWARE\Mozilla\Minefield"))
{
  foreach item (registry_enum_keys(key:"SOFTWARE\Mozilla\Minefield"))
  {
    ver = eregmatch(pattern:"([0-9.]+a1pre)", string:item);
    # Firefox 3.6a1pre or 3.7a1pre Version check
    if(ver[1] =~ "3\.[6|7]a1pre")
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
