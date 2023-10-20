# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809788");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-1666");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-01 11:05:47 +0530 (Wed, 01 Feb 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation Insecure 'tpfc.dll' Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"VMware Workstation is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to loading of insecure
  'tpfc.dll' library in thinprint.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to execute arbitrary code with the privileges of the user running
  the affected application.");

  script_tag(name:"affected", value:"VMware Workstation version 8.x before
  8.0.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Workstation version
  8.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://cve.circl.lu/cve/CVE-2012-1666");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55421");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Workstation/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^8\.")
{
  if(version_is_less(version:vmwareVer, test_version:"8.0.4"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"8.0.4");
    security_message(data:report);
    exit(0);
  }
}
