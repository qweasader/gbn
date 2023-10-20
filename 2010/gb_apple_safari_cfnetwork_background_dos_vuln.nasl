# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800485");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0924");
  script_name("Apple Safari 'background' Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("AppleSafari/Version");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38447");
  script_xref(name:"URL", value:"http://nobytes.com/exploits/Safari_4.0.4_background_DoS_pl.txt");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the affected
  browser, resulting in a denial of service condition and can cause other attacks.");

  script_tag(name:"affected", value:"Apple Safari version 4.0.3 (4.31.9.1) and 4.0.4 (5.31.21.10).");

  script_tag(name:"insight", value:"The flaw exists due to error in 'cfnetwork.dll' file in
  CFNetwork when processing 'BACKGROUND' attribute of a 'BODY' element via a long string.");

  script_tag(name:"solution", value:"Update to version 4.0.5 or later.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

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
          if(version_is_equal(version:dllVer, test_version:"1.450.5.0")) {
            report = report_fixed_ver(installed_version:dllVer, fixed_version:"Safari 4.0.5", install_path:path, file_checked:file);
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
