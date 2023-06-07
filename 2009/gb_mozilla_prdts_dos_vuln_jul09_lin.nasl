###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products 'select()' Denial Of Service Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800849");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2535", "CVE-2009-1692");
  script_name("Mozilla Products 'select()' DoS Vulnerability - Linux");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35446");
  script_xref(name:"URL", value:"http://www.g-sec.lu/one-bug-to-rule-them-all.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause application crash by
  consuming the memory.");

  script_tag(name:"affected", value:"Mozilla Seamonkey version prior to 1.1.17

  Mozilla Thunderbird version 2.0.0.22 and prior

  Mozilla Firefox version before 2.0.0.19 and 3.x before 3.0.5.");

  script_tag(name:"insight", value:"A null pointer dereference error occurs while calling the 'select' method
  with a large integer, that results in continuous allocation of x+n bytes of
  memory, exhausting memory after a while.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 2.0.0.19 or 3.0.5 or later

  Update to Mozilla Seamonkey version 1.1.17 or later

  Apply patch for Mozilla Thunderbird through Mozilla engine update");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"2.0.0.19")||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"1.1.17"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer != NULL)
{
  if(version_is_less_equal(version:tbVer, test_version:"2.0.0.22")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
