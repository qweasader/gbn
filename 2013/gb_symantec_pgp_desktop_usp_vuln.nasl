# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:pgp_desktop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803890");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2010-3397");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-10 13:52:56 +0530 (Tue, 10 Sep 2013)");
  script_name("Symantec PGP Desktop Untrusted Search Path Vulnerability");


  script_tag(name:"summary", value:"Symantec PGP Desktop is prone to untrusted search path vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 10.0.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaws is due to the application loading libraries (e.g. tvttsp.dll, tsp.dll)
in an insecure manner.");
  script_tag(name:"affected", value:"Symantec PGP Desktop 9.9.0 Build 397, 9.10.x, 10.x prior to 10.0.0 Build 2732");
  script_tag(name:"impact", value:"Successful exploitation will allow remote unauthenticated attacker to execute
arbitrary code and conduct DLL hijacking attacks.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42856");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Sep/170");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!rpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:rpVer, test_version:"9.9.0.397") ||
   version_in_range(version:rpVer, test_version:"9.10.0", test_version2:"10.0.0.2732"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
