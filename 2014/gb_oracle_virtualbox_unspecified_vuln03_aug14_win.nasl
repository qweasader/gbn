# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804696");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2014-4228");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-08-04 10:51:06 +0530 (Mon, 04 Aug 2014)");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability-03 Aug2014 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59510");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68601");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to unspecified error related to the Graphics driver (WDDM)
  for Windows guests.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to affect confidentiality,
  integrity, and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle VM VirtualBox before versions 4.1.34, 4.2.26, and 4.3.12.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:oracle:vm_virtualbox", "cpe:/a:sun:virtualbox");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\.[1-3]") {
  if(version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.33")||
     version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.25")||
     version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.11")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
