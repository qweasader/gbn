# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107380");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-2345");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-26 11:55:31 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("DameWare Mini Remote Control < 12.0.3 Buffer Overflow Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dameware_mini_rc_detect_win.nasl");
  script_mandatory_keys("solarwinds/dameware_mini_remote_control/detected");

  script_tag(name:"summary", value:"DameWare Mini Remote Control is prone to a local buffer
  overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A certain message parsing function inside the Dameware Mini Remote
  Control service does not properly validate the input size of an incoming string before passing it to
  wsprintfw.

  As a result, a specially crafted message can overflow into the bordering format field and subsequently
  overflow the stack frame.");

  script_tag(name:"impact", value:"Exploitation of this vulnerability does not require authentication and
  can lead to SYSTEM level privilege on any system running the dwmrcs daemon.");

  script_tag(name:"affected", value:"DameWare Mini Remote Control before version 12.0.3.");

  script_tag(name:"solution", value:"Upgrade DameWare Mini Remote Control to version 12.0.3 or later.");

  script_xref(name:"URL", value:"https://support.solarwinds.com/Success_Center/DameWare_Remote_Support_Mini_Remote_Control/Knowledgebase_Articles/CVE-2016-2345_vulnerability");

  exit(0);
}

CPE = "cpe:/a:solarwinds:dameware_mini_remote_control";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
