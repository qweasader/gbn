# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814035");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-21 12:06:57 +0530 (Fri, 21 Sep 2018)");
  script_name("Adobe Reader End Of Life Detection (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");

  script_xref(name:"URL", value:"https://helpx.adobe.com/support/programs/eol-matrix.html");

  script_tag(name:"summary", value:"The Adobe Reader version on the remote host
  has reached the end of life and should not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of Adobe Reader is not
  receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Adobe Reader version on the remote
  host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an unsupported version is present
  on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {

  report = build_eol_message( name:"Adobe Reader",
                              cpe:CPE,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
