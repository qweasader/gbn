# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800982");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4589");
  script_name("MediaWiki XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35662");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51687");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2009-July/000087.html");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.14/mediawiki-1.14.1.patch.gz");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.15/mediawiki-1.15.1.patch.gz");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.14/mediawiki-1.14.1.tar.gz");
  script_xref(name:"URL", value:"http://download.wikimedia.org/mediawiki/1.15/mediawiki-1.15.1.tar.gz");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include arbitrary
  HTML or web scripts in the scope of the browser and allows to obtain sensitive information.");

  script_tag(name:"affected", value:"MediaWiki version 1.14.0

  MediaWiki version 1.15.0");

  script_tag(name:"insight", value:"The flaw is due to the error in 'Special:Block' script in the
  'getContribsLink' function in 'SpecialBlockip.php' page. It fails to properly sanitize user-supplied
  input while processing the 'ip' parameter.");

  script_tag(name:"solution", value:"Apply the patch from the referenced or upgrade to version 1.14.1, 1.15.1 or later.");

  script_tag(name:"summary", value:"MediaWiki is prone to XSS Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"1.14.0" ) ||
    version_is_equal( version:vers, test_version:"1.15.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.14.1 or 1.15.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );