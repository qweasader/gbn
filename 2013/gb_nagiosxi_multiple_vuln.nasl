# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagiosxi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803168");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-07 18:25:24 +0530 (Thu, 07 Feb 2013)");
  script_name("Nagios XI Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52011");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120038");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Feb/10");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagiosxi/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
spoofing, cross-site scripting and cross-site request forgery attacks.");
  script_tag(name:"affected", value:"Nagios XI versions 2012R1.5b and 2012R1.5");
  script_tag(name:"insight", value:"- Input passed via the 'xiwindow' GET parameter to admin/index.php
is not properly verified before being used to be displayed as iframe.

  - Input passed via multiple GET parameters to various scripts is not properly
  sanitized before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without properly verifying the requests.

  - Input passed via the 'address' POST parameter to
  includes/components/autodiscovery/index.php (when 'mode' is set to 'newjob',
  'update' is set to '1', and 'job' is set to '-1') is not properly verified
  before being used. This can be exploited to inject and execute arbitrary
  shell commands.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Nagios XI is prone to multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if("unknown" >!< vers && (vers == "2012R1.5b" || vers == "2012R1.5"))
{
  security_message(port);
  exit(0);
}
