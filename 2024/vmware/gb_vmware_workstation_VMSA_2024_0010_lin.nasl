# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834026");
  script_version("2024-05-24T19:38:34+0000");
  script_cve_id("CVE-2024-22267", "CVE-2024-22268", "CVE-2024-22269", "CVE-2024-22270");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-23 06:06:06 +0530 (Thu, 23 May 2024)");
  script_name("VMware Workstation Multiple Vulnerabilities (VMSA_2024_0010) - Linux");

  script_tag(name:"summary", value:"VMware Workstation is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-22267: A use-after-free vulnerability in the vbluetooth device.

  - CVE-2024-22268: An heap buffer-overflow vulnerability in the Shader functionality.

  - CVE-2024-22269: An information disclosure vulnerability in the vbluetooth device.

  - CVE-2024-22270: An information disclosure vulnerability in the Host Guest File Sharing (HGFS) functionality.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, information disclosure and cause denial of service
  attacks.");

  script_tag(name:"affected", value:"VMware Workstation 17.x before 17.5.2 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 17.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24280");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed", "VMware/Workstation/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^17\." && version_is_less(version:vers, test_version:"17.5.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.5.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
