# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818126");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2021-2145", "CVE-2021-2250", "CVE-2021-2264", "CVE-2021-2266",
                "CVE-2021-2279", "CVE-2021-2280", "CVE-2021-2281", "CVE-2021-2282",
                "CVE-2021-2283", "CVE-2021-2284", "CVE-2021-2285", "CVE-2021-2286",
                "CVE-2021-2287", "CVE-2021-2291", "CVE-2021-2296", "CVE-2021-2297",
                "CVE-2021-2306", "CVE-2021-2309", "CVE-2021-2310", "CVE-2021-2312",
                "CVE-2021-2321");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-27 19:10:00 +0000 (Tue, 27 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-05-17 12:44:14 +0530 (Mon, 17 May 2021)");
  script_name("Oracle VirtualBox Security Update (cpuapr2021) - Windows");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component of VirtualBox.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 6.1.20 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 6.1.20
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:vm_virtualbox", "cpe:/a:sun:virtualbox");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.1.20")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.20", install_path:path);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
