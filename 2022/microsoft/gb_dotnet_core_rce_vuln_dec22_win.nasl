# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826738");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2022-41089");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 17:39:00 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-12-15 17:47:33 +0530 (Thu, 15 Dec 2022)");
  script_name(".NET Core Remote Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:".NET Core is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to incorrect processing
  of user-supplied data in .NET.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to disclose sensitive information and allow to spoof page content.");

  script_tag(name:"affected", value:".NET Core runtime 7.0 before 7.0.1, 6.0 before
  6.0.12, 3.1 before 3.1.32 and .NET Core SDK before 6.0.112 and 6.0.307,
  3.1 before 3.1.426 and 7.0 before 7.0.101.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  7.0.1 or 6.0.12 or 3.1.32 or later or upgrade .NET Core SDK to versions 6.0.112 or
  6.0.307 or 7.0.101 or 3.1.426 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.32/3.1.32.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.12/6.0.12.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.1/7.0.1.md");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if(!coreVers || coreVers !~ "^(3\.1|[6|7]\.0)"){
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver"))
{
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer)
{
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.11")){
    fix = "6.0.12 or later";
  }
  else if(version_in_range(version:corerunVer, test_version:"3.1", test_version2:"3.1.31")){
    fix = "3.1.32 or later";
  }
  else if(version_in_range_exclusive(version:corerunVer, test_version_lo: "7.0", test_version_up: "7.0.1")){
    fix = "7.0.1 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.111") ||
     version_in_range(version:codesdkVer, test_version:"6.0.300", test_version2:"6.0.306")){
    fix1 = "6.0.112 or 6.0.307 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"3.1", test_version2:"3.1.425")){
    fix1 = "3.1.426 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"7.0", test_version2:"7.0.100")){
    fix1 = "7.0.101 or later";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(data:report);
  exit(0);
}

else if(fix1)
{
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
