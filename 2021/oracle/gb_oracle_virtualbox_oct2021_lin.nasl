# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818837");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2021-35538", "CVE-2021-35545", "CVE-2021-35540", "CVE-2021-35542",
                "CVE-2021-2475");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-26 13:35:00 +0000 (Tue, 26 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-25 16:20:35 +0530 (Mon, 25 Oct 2021)");
  script_name("Oracle VirtualBox Security Update (cpuoct2021) - Linux");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions 6.1.x prior to 6.1.28
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 6.1.28
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^6\.1\." && version_is_less(version:version, test_version:"6.1.28")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.1.28", install_path:path);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
