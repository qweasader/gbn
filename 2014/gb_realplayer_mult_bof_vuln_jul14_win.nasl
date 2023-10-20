# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:realnetworks:realplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804678");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-3113");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-14 16:18:41 +0530 (Mon, 14 Jul 2014)");
  script_name("RealNetworks RealPlayer Multiple Buffer Overflow Vulnerabilities July14 (Windows)");

  script_tag(name:"summary", value:"RealPlayer is prone to multiple buffer overflow vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to improper validation when handling corrupt index types or
incorrect media sample sizes.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a buffer
overflow, resulting in a denial of service or potentially allowing the
execution of arbitrary code.");
  script_tag(name:"affected", value:"RealNetworks RealPlayer before version 17.0.10.8 on Windows.");
  script_tag(name:"solution", value:"Upgrade to RealNetworks RealPlayer version 17.0.10.8 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59238");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68442");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/06272014_player/en/");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-14-001");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-14-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!realVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:realVer, test_version:"17.0.10.8"))
{
  report = report_fixed_ver(installed_version:realVer, fixed_version:"17.0.10.8");
  security_message(port:0, data:report);
  exit(0);
}
