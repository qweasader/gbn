###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Same Origin Policy Bypass Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802183");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-2999");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mozilla Products Same Origin Policy Bypass Vulnerability (MAC OS X)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-38.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49848");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass the same-origin policy,
  execute arbitrary script code, obtain potentially sensitive information, or
  launch spoofing attacks against other sites.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.3
  Thunderbird version prior to 6.0
  Mozilla Firefox before 3.6.23 and 4.x through 5");
  script_tag(name:"insight", value:"The flaw is due to some plugins, which use the value of
  'window.location' to determine the page origin this could fool the plugin
  into granting the plugin content access to another site or the local file
  system in violation of the Same Origin Policy.");
  script_tag(name:"summary", value:"Mozilla firefox/thunderbird/seamonkey is prone to same origin policy bypass vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.23 or 6.0 or later, Upgrade to SeaMonkey version to 2.3 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.23")||
     version_in_range(version:vers, test_version:"4.0", test_version2:"5.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"6.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
