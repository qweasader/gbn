# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819962");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2021-43896");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-23 17:48:00 +0000 (Thu, 23 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-01-18 11:37:10 +0530 (Tue, 18 Jan 2022)");
  script_name("Microsoft PowerShell Spoofing Vulnerability (Dec 2021) - Windows");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2021-43896.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when specially crafted ANSI
  control sequences are used through the pipeline to create executable code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing attack.");

  script_tag(name:"affected", value:"PowerShell Core versions 7.0 prior to 7.2.1
  on Windows.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 7.2.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/28");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43896");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers =~ "^7\." && version_is_less(version:vers, test_version:"7.2.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.2.1", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
