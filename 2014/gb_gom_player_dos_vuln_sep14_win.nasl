# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gomlab:gom_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804903");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-3899");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-15 12:54:27 +0530 (Mon, 15 Sep 2014)");

  script_name("GOM Media Player Denial of Service Vulnerability Sep14 (Windows)");

  script_tag(name:"summary", value:"GOM Media Player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error
  in processing a malformed image file. resulting in a loss of availability
  for the program");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"GOM Media Player version 2.2.51.5149
  and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to GOM Media Player version 2.2.62.5209
  or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.xforce.iss.net/xforce/xfdb/95133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69182");
  script_xref(name:"URL", value:"https://cxsecurity.com/cveshow/CVE-2014-3899");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2014/JVNDB-2014-000085.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_gom_player_detect_win.nasl");
  script_mandatory_keys("GOM/Player/Ver/Win");
  script_xref(name:"URL", value:"http://www.gomlab.com/eng/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!gomVer = get_app_version(cpe:CPE)){
  exit(0);
}

if( version_is_less_equal(version:gomVer, test_version:"2.2.51.5149"))
{
  report = report_fixed_ver(installed_version:gomVer, vulnerable_range:"Less than or equal to 2.2.51.5149");
  security_message(port:0, data:report);
  exit(0);
}
