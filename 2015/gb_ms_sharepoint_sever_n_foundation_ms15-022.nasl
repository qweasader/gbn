###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server and Foundation Multiple Vulnerabilities (3038999)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805151");
  script_version("2020-06-09T05:48:43+0000");
  script_cve_id("CVE-2015-0085", "CVE-2015-1633", "CVE-2015-1636");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2015-03-11 16:48:56 +0530 (Wed, 11 Mar 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Server and Foundation Multiple Vulnerabilities (3038999)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due,

  - An use-after-free error that is triggered when handling a specially crafted
  office file.

  - User-supplied input is not properly validated before returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to dereference already freed memory and potentially execute
  arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2010 Service Pack 2

  - Microsoft SharePoint Foundation 2010 Service Pack 2

  - Microsoft SharePoint Foundation 2013 Service Pack 1 and prior

  - Microsoft SharePoint Server 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2956208");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2956175");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-022");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server_or_Foundation_or_Services/Installed");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\";
if(!registry_key_exists(key:key))
  exit(0);

cpe_list = make_list("cpe:/a:microsoft:sharepoint_server", "cpe:/a:microsoft:sharepoint_foundation");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
if(!path || "Could not find the install location" >< path)
  exit(0);

# nb: SharePoint Server and Foundation 2010 (wssloc)
if(vers =~ "^14\.") {
  check_path = registry_get_sz(key:key + "14.0", item:"Location");
  if(check_path) {
    check_file = "BIN\Onetutil.dll";

    dllVer = fetch_file_version(sysPath:check_path, file_name:check_file);
    if(dllVer) {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7145.4999")) {
        report = report_fixed_ver(file_checked:check_path + "\" + check_file, installed_version:dllVer, vulnerable_range:"14.0 - 14.0.7145.4999", install_path:path);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

# nb: SharePoint Server and Foundation 2013 only for (sts)
else if(vers =~ "^15\.") {
  check_path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(check_path) {
    check_path += "\microsoft shared\SERVER15\Server Setup Controller";
    check_file = "Wsssetup.dll";

    dllVer = fetch_file_version(sysPath:check_path, file_name:check_file);
    if(dllVer) {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4701.999")) {
        report = report_fixed_ver(file_checked:check_path + "\" + check_file, installed_version:dllVer, vulnerable_range:"15.0 - 15.0.4701.999", install_path:path);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
