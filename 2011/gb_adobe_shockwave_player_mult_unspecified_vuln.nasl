###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Unspecified Vulnerabilities
#
# Authors:
# N Shashi Kiran <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802301");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-21 13:52:36 +0200 (Tue, 21 Jun 2011)");
  script_cve_id("CVE-2011-0317", "CVE-2011-0318", "CVE-2011-0319", "CVE-2011-0320",
                "CVE-2011-0335", "CVE-2011-2108", "CVE-2011-2109", "CVE-2011-2111",
                "CVE-2011-2112", "CVE-2011-2113", "CVE-2011-2114", "CVE-2011-2115",
                "CVE-2011-2118", "CVE-2011-2119", "CVE-2011-2120", "CVE-2011-2121",
                "CVE-2011-2122", "CVE-2011-2123", "CVE-2011-2124", "CVE-2011-2125",
                "CVE-2011-2126", "CVE-2011-2127", "CVE-2011-2128");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-17.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48273");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48275");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48278");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48284");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48286");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48289");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48298");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48300");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48302");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48304");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48306");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48307");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48310");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48311");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");

  script_tag(name:"impact", value:"Successful attack could allow attackers to execute of arbitrary code or
  cause a denial of service.");

  script_tag(name:"affected", value:"Adobe Shockwave Player version before 11.6.0.626 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to unspecified vectors. Please see the references
  for more details.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 11.6.0.626 or later.");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.6.0.626")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.6.0.626");
  security_message(port: 0, data: report);
}
