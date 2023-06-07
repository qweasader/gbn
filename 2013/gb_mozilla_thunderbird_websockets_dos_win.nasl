###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird 'WebSockets' Denial of Service Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803392");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-4191");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Thunderbird 'WebSockets' Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55889");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-88.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code via unspecified vectors.");

  script_tag(name:"affected", value:"Thunderbird versions before 16.0.1 on Windows.");

  script_tag(name:"insight", value:"Error in the WebSockets implementation, allows remote attackers to cause a
  denial of service.");

  script_tag(name:"solution", value:"Upgrade to Thunderbird version to 16.0.1 or later.");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"16.0.1")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.0.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}
