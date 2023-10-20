# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108428");
  script_version("2023-09-19T05:06:03+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:03 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-03-12 08:45:04 +0100 (Mon, 12 Mar 2018)");
  script_name("ILIAS End Of Life Detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_xref(name:"URL", value:"https://www.ilias.de/docu/goto.php?target=wiki_1357&client_id=docu#ilPageTocA115");
  script_xref(name:"URL", value:"https://www.ilias.de/docu/ilias.php?ref_id=1719&obj_id=6543&cmd=layout&cmdClass=illmpresentationgui&cmdNode=wc&baseClass=ilLMPresentationGUI");

  script_tag(name:"summary", value:"The ILIAS version on the remote host has reached the end of life and should
  not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of ILIAS is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the ILIAS version on the remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version  = infos["version"];
location = infos["location"];

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {
  report = build_eol_message( name:"ILIAS",
                              cpe:CPE,
                              version:version,
                              location:location,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
