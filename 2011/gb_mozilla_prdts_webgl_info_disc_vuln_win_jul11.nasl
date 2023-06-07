###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products WebGL Information Disclosure Vulnerability July-11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802211");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_cve_id("CVE-2011-2366");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Mozilla Products WebGL Information Disclosure Vulnerability July-11 (Windows)");

  script_xref(name:"URL", value:"http://www.contextis.co.uk/resources/blog/webgl/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48319");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=656277");
  script_xref(name:"URL", value:"https://developer.mozilla.org/en/WebGL/Cross-Domain_Textures");
  script_xref(name:"URL", value:"https://hacks.mozilla.org/2011/06/cross-domain-webgl-textures-disabled-in-firefox-5/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.");
  script_tag(name:"affected", value:"Thunderbird versions before 5.0
  Mozilla Firefox versions before 5.0");
  script_tag(name:"insight", value:"The flaw is due to an error in WebGL, which allows remote attackers to
  obtain approximate copies of arbitrary images via a timing attack involving
  a crafted WebGL fragment shader.");
  script_tag(name:"summary", value:"Mozilla Firefox or Thunderbird is prone to an information disclosure vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 5.0 or later,
  Upgrade to Thunderbird version 5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");


vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"5.0"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"5.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"5.0")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"5.0");
    security_message(port: 0, data: report);
  }
}
