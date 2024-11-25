# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803158");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148",
                "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5151", "CVE-2012-5152",
                "CVE-2012-5153", "CVE-2012-5156", "CVE-2012-5157", "CVE-2013-0828",
                "CVE-2013-0829", "CVE-2013-0831", "CVE-2013-0832", "CVE-2013-0833",
                "CVE-2013-0834", "CVE-2013-0835", "CVE-2013-0836", "CVE-2013-0837",
                "CVE-2013-0838");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-17 14:48:24 +0530 (Thu, 17 Jan 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Jan 2013) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51825/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57251");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027977");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/01/stable-channel-update.html");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 24.0.1312.52 on Linux");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 24.0.1312.52 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"24.0.1312.52")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"24.0.1312.52");
  security_message(port: 0, data: report);
}
