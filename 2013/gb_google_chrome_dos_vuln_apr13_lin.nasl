# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803356");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-2632");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-02 11:17:26 +0530 (Tue, 02 Apr 2013)");
  script_name("Google Chrome Denial of Service Vulnerability - April 13 (Linux)");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-2632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58697");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/03/dev-channel-update_18.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial-of-service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 27.0.1444.3 on Linux");
  script_tag(name:"insight", value:"User-supplied input is not properly sanitized when parsing JavaScript in
  'Google V8' JavaScript Engine.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 27.0.1444.3 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"27.0.1444.3"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"27.0.1444.3");
  security_message(port: 0, data: report);
  exit(0);
}
