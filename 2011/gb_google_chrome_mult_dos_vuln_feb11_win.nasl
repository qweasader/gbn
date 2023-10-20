# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801747");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_cve_id("CVE-2011-0981", "CVE-2011-0982", "CVE-2011-0983",
                "CVE-2011-0984", "CVE-2011-0985");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities - February 11(Windows)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_08.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial-of-service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 9.0.597.94");
  script_tag(name:"insight", value:"The flaws are due to

  - Not properly performing event handling for animations

  - a use-after-free error in SVG font faces

  - Not properly handling anonymous blocks

  - Out-of-bounds read in plug-in handling

  - Not properly performing process termination upon memory exhaustion");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 9.0.597.94 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"9.0.597.94")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"9.0.597.94");
  security_message(port: 0, data: report);
}
