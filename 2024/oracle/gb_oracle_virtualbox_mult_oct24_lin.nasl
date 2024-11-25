# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834693");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-21253");
  script_tag(name:"cvss_base", value:"1.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:15 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-16 16:21:24 +0530 (Wed, 16 Oct 2024)");
  script_name("Oracle VirtualBox Security Update (oct24) - Linux");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to a denial
  of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Core component of Oracle VM VirtualBox");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service attacks.");

  script_tag(name:"affected", value:"Oracle VM VirtualBox version 7.0.x prior
  to 7.0.22 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.0.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2024.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^7\.0\." && version_is_less(version:vers, test_version:"7.0.22")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.22", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
