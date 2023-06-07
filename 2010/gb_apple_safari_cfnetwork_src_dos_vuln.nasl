###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari 'SRC' Remote Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800486");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0925");
  script_name("Apple Safari 'SRC' Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("AppleSafari/Version");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/391341.php");
  script_xref(name:"URL", value:"http://nobytes.com/exploits/Safari_4.0.4_background_DoS_pl.txt");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the affected
  browser, resulting in a denial of service condition and can cause other attacks.");

  script_tag(name:"affected", value:"Apple Safari version 4.0.4 (5.31.21.10).");

  script_tag(name:"insight", value:"The flaw exists due to error in 'cfnetwork.dll' file in
  CFNetwork when, processing 'SRC' attribute of a 'IMG' or 'IFRAME' element via a long string.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

function find_version(filepath) {
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:filepath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:filepath);
  dllVer = GetVer(file:file, share:share);
  return dllVer;
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.31.21.10")) {
  key = "SOFTWARE\Apple Computer, Inc.\Safari";
  asFile = registry_get_sz(item:"BrowserExe", key:key);
  if(asFile) {
    exeVer = find_version(filepath:asFile);
    if(!isnull(exeVer)) {
      if(version_is_less_equal(version:exeVer, test_version:"5.31.21.10")) {
        file = asFile -"Safari.exe" + "cfnetwork.dll";
        dllVer = find_version(filepath:file);
        if(isnull(dllVer)) {
          file = asFile - "\Safari\Safari.exe\Common Files\Apple\Apple Application Support\cfnetwork.dll";
          dllVer = find_version(filepath:file);
        }

        if(!isnull(dllVer)) {
          if(version_is_less_equal(version:dllVer, test_version:"1.450.5.0")) {
            report = report_fixed_ver(installed_version:dllVer, fixed_version:"None", install_path:path, file_checked:file);
            security_message(port:0, data:report);
            exit(0);
          }
          exit(99);
        }
      }
    }
  }
}

exit(0);
