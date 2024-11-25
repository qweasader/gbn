# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103537");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_version("2024-06-28T05:05:33+0000");

  script_name("ESVA (E-Mail Security Virtual Appliance) RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20551/");

  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-08-16 14:33:49 +0200 (Thu, 16 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ESVA (E-Mail Security Virtual Appliance) is prone to a remote code-execution vulnerability.");
  script_tag(name:"impact", value:"Successful exploits will allow the attacker to execute arbitrary code within the context of
the application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = '/released.html';

if(http_vuln_check(port:port, url:url,pattern:"<title>--=.*- Message released from quarantine", usecache:TRUE)) {

  url = '/cgi-bin/learn-msg.cgi?id=|id;';

  if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
