# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emc:rsa_authentication_agent";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803749");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2013-0931");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-28 11:21:00 +0530 (Wed, 28 Aug 2013)");
  script_name("RSA Authentication Agent Authentication Bypass Vulnerability - Windows");


  script_tag(name:"summary", value:"RSA Authentication Agent is prone to an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 7.1.2 or later.");
  script_tag(name:"insight", value:"The flaw is triggered when a session is activated from the active screensaver
after the Quick PIN Unlock timeout has expired, which will result in an
incorrect prompt for a PIN as opposed to a prompt for the full passcode.");
  script_tag(name:"affected", value:"RSA Authentication Agent version 7.1.x before 7.1.2 on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow local attacker to bypass certain security
restrictions and gain unauthorized privileged access.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1028230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58248");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/438433.php");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120606");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/att-0/ESA-2013-012.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-03/att-0001/ESA-2013-012.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_rsa_auth_agent_detect_win.nasl");
  script_mandatory_keys("RSA/AuthenticationAgent6432/Installed");
  script_xref(name:"URL", value:"http://www.rsa.com/node.aspx?id=2575");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

rasAutVer = get_app_version(cpe:CPE);
if(rasAutVer && rasAutVer =~ "^7\.1")
{
  if(version_is_less(version:rasAutVer, test_version:"7.1.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
