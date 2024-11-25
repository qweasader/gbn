# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832630");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2023-36049", "CVE-2023-36558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 19:25:00 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 11:59:24 +0530 (Thu, 16 Nov 2023)");
  script_name(".NET Core Multiple Vulnerabilities - Windows");

  script_tag(name:"summary", value:".NET Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A security feature bypass vulnerability exists in ASP.NET where an unauthenticated
    user is able to bypass validation on Blazor server forms which could trigger
    unintended actions.

  - An elevation of privilege vulnerability exists in .NET where untrusted URIs
    provided to System.Net.WebRequest.Create can be used to inject arbitrary commands
    to backend FTP servers.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to bypass security restrictions and elevate privileges on an affected
  system.");

  script_tag(name:"affected", value:".NET Core runtime 7.0 before 7.0.14, 6.0 before
  6.0.25, 8.0 before 8.0.0 and .NET Core SDK before 7.0.114, 6.0.317, 8.0.100.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions 7.0.14 or
  6.0.25 or 8.0.0 or later or upgrade .NET Core SDK to versions 6.0.317 or 7.0.114 or
  8.0.100 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/288");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/287");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if(!coreVers || coreVers !~ "^[6|7|8]\.0"){
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
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.24")){
    fix = "6.0.25 or later";
  }
  else if(version_in_range(version:corerunVer, test_version:"7.0", test_version2:"7.0.13")){
    fix = "7.0.14 or later";
  }
  ## .NET 8.0 RC2 or earlier is vulnerable
  else if(corerunVer =~ "^8\.0\.0" && corerunVer !~ "^8\.0\.0$"){
    fix = "8.0.0 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.316")){
    fix1 = "6.0.317 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"7.0", test_version2:"7.0.113")){
    fix1 = "7.0.114 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"8.0", test_version2:"8.0.99")){
    fix1 = "8.0.100 or later";
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

exit(99);
