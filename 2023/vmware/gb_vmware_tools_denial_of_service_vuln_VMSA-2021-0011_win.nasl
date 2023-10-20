# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826755");
  script_version("2023-06-29T05:05:23+0000");
  script_cve_id("CVE-2021-21997");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 18:50:00 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2023-01-10 15:43:23 +0530 (Tue, 10 Jan 2023)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Tools Denial of Service Vulnerability (VMSA-2021-0011) - Windows");

  script_tag(name:"summary", value:"VMware Tools is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a vulnerability in the
  VM3DMP driver.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  with local user privileges in the Windows guest operating system, where VMware Tools
  is installed, can trigger a PANIC in the VM3DMP driver leading to a
  denial-of-service condition in the Windows guest operating system.");

  script_tag(name:"affected", value:"VMware Tools 11.x.y prior to 11.3.0 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Tool version 11.3.0 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2021-0011.html");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_tools_detect_win.nasl");
  script_mandatory_keys("VMwareTools/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^11\." && version_is_less(version:vers, test_version:"11.3.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.3.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
