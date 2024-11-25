# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806807");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-01-14 18:46:02 +0530 (Thu, 14 Jan 2016)");
  script_name("pfSense Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of pfSense.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

pfsPort = http_get_port(default:443);

rcvRes = http_get_cache(item:"/", port:pfsPort);

if('pfsense' >< rcvRes && ('>Login to pfSense<' >< rcvRes ||
   '/themes/pfsense_ng' >< rcvRes || '<title id="pfsense-logo-svg">pfSense Logo</title>' >< rcvRes))
{
  set_kb_item(name:"pfsense/installed", value:TRUE);
  set_kb_item(name:"pfsense/http/installed", value:TRUE);
  set_kb_item(name:"pfsense/http/port", value:pfsPort);

  vers = 'unknown';
}

exit(0);
