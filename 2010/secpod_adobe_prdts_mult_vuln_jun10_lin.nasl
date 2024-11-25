# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902194");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2008-4546", "CVE-2009-3793", "CVE-2010-1297", "CVE-2010-2160",
                "CVE-2010-2161", "CVE-2010-2162", "CVE-2010-2163", "CVE-2010-2164",
                "CVE-2010-2165", "CVE-2010-2166", "CVE-2010-2167", "CVE-2010-2169",
                "CVE-2010-2170", "CVE-2010-2171", "CVE-2010-2172", "CVE-2010-2173",
                "CVE-2010-2174", "CVE-2010-2175", "CVE-2010-2176", "CVE-2010-2177",
                "CVE-2010-2178", "CVE-2010-2179", "CVE-2010-2180", "CVE-2010-2181",
                "CVE-2010-2182", "CVE-2010-2183", "CVE-2010-2184", "CVE-2010-2185",
                "CVE-2010-2186", "CVE-2010-2187", "CVE-2010-2188", "CVE-2010-2189");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:20:44 +0000 (Fri, 28 Jun 2024)");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities (Jun 2010) - Linux");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40759");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jun/1024086.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information or cause a denial of service.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 2.0.2.12610,
  Adobe Flash Player before 9.0.277.0 and 10.x before 10.1.53.64 on Linux.");

  script_tag(name:"insight", value:"The flaws are due to input validation errors, memory corruptions,
  array indexing, use-after-free, integer and buffer overflows, and
  invalid pointers when processing malformed Flash content.");

  script_tag(name:"solution", value:"Update to Adobe Air 2.0.2.12610 or Adobe Flash Player 9.0.277.0 or 10.0.45.2.");

  script_tag(name:"summary", value:"Adobe Flash Player/Air is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:flash_player",
                     "cpe:/a:adobe:adobe_air");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:flash_player") {
  if(version_is_less(version:vers, test_version:"9.0.277.0") ||
     version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.45.1")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.0.277.0/10.0.45.2", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:adobe_air") {
  if(version_is_less(version:vers, test_version:"2.0.2.12610")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.0.2.12610", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
