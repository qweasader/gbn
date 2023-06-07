###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Nested 'object' Tag Remote Denial Of Service vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800744");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1131");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Apple Safari Nested 'object' Tag Remote Denial Of Service vulnerability");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=7517");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38884");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392298.php");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/38884.php");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to crash the
  affected browser.");

  script_tag(name:"affected", value:"Apple Safari 4.0.5 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'JavaScriptCore.dll' when
  processing HTML document composed of many successive occurrences of the '<object>' substring.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Apple Safari is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.31.22.7")) {
  dllPath = registry_get_sz(key:"SOFTWARE\Apple Inc.\Apple Application Support", item:"InstallDir");
  if(!isnull(dllPath)) {
    dllPath += "\JavaScriptCore.dll";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    dllVer = GetVer(file:file, share:share);
    if(dllVer) {
      if(version_is_less_equal(version:dllVer, test_version:"5.31.22.5")) {
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"None", install_path:path, file_checked:dllPath);
        security_message(port:0, data:report);
        exit(0);
      }
      exit(99);
    }
  }
}

exit(0);
