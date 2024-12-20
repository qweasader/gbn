# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106288");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-27 11:26:32 +0700 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EMC Avamar Detection");

  script_tag(name:"summary", value:"Detection of EMC Avamar.

  The script sends a connection request to the server and attempts to detect the presence of Avamar and to
  extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.emc.com/data-protection/avamar.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/dtlt/home.html");

if ( ( "<title>EMC Avamar" >< res && "dtlt-banner-product-name-avamar" >< res ) || "Server: Avamar" >< res ) {

  version = "unknown";

  permut = rand_str( length:32, charset:"ABCDEF1234567890" );
  host = http_host_name( port:port );
  useragent = http_get_user_agent();

  data = '5|0|6|https://' + get_host_ip() + '/avi/avigui/|' + rand_str( length:32, charset:"ABCDEF1234567890" ) + '|com.avamar.avinstaller.gwt.shared.AvinstallerService|getAviVersion|java.lang.String/|' + get_host_ip() + '|1|2|3|4|1|5|6|';
  len = strlen( data );

  req = 'POST /avi/avigui/avigwt HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent  + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Content-Type: text/x-gwt-rpc; charset=utf-8\r\n' +
        'X-GWT-Permutation: ' + permut  + '\r\n' +
        'X-GWT-Module-Base: https://' + host + '/avi/avigui/\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Connection: close\r\n' +
        '\r\n' +
        data;

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf && '//OK[1,["' >< buf )
  {
    # //OK[1,["7.3.1.125"],0,7]
    v = eregmatch( pattern:'\\["([0-9.-]+)"\\]', string:buf );
    if( ! isnull( v[1] ) )
    {
      version = v[1];
      replace_kb_item(name: "emc_avamar/version", value: version);
    }
  }

  if( version == "unknown" )
  {
    req = http_get(port: port, item: "/dtlt/wr_about.html");
    res = http_keepalive_send_recv(port: port, data: req);

    #
    vers = eregmatch(pattern: "Version ([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      replace_kb_item(name: "emc_avamar/version", value: version);
    }
  }

  set_kb_item(name: "emc_avamar/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:emc:avamar:");
  if (!cpe)
    cpe = 'cpe:/a:emc:avamar';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "EMC Avamar", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
