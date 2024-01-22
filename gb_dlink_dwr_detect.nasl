# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113293");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-11-08 16:44:00 +0100 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("D-Link DWR Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("D-LinkDWR/banner");

  script_xref(name:"URL", value:"https://dlink.com");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DWR (Router) devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

port = http_get_port( default: 80 );

url = "/EXCU_SHELL";
req = http_get_req( port: port, url: url, add_headers: make_array( "cmdnum", "1", "command1", "wrt -x get wrt.system.version", "confirm1", "n" ),
                    accept_header: "*/*", host_header_use_ip: TRUE );
res = http_keepalive_send_recv( port: port, data: req );

# nb: Both for DWR-711, have "Server: GoAhead-Webs" banner
# <?xml version="1.0" encoding="utf-8"?><version type="option" get="getSdkVersion" value="DWR-711_A1_FW1.09_00(20160902)" />
info = eregmatch( string: res, pattern: ' value="([^"]+)"', icase: FALSE );
if( res =~ "^HTTP/1\.[01] 200" && info[1] && info[1] =~ "^DWR-[0-9]+" ) {
  infos = info[1];
  detected = TRUE;
  concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
}

if( ! detected ) {
  url = "/js/func.js";
  res = http_get_cache( port: port, item: url );
  # model_name="DWR-711"
  info = eregmatch( string: res, pattern: 'model_name="([^"]+)"', icase: FALSE );
  if( res =~ "^HTTP/1\.[01] 200" && info[1] && info[1] =~ "^DWR-[0-9]+" ) {
    infos = info[1];
    detected = TRUE;
    concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
  }
}

# nb: DWR-932, has "Server: server" banner
if( ! detected ) {
  url = "/data.ria?DynUpdate=about_sys";
  res = http_get_cache( port: port, item: url );
  # {"modem_ver":"DTLW1_R705B_1.0.4_171122","hw_ver":"E1","imei":"1234567890","imsi":"1234567890","model_name":"DWR-932","fw_ver":"01.02.EU","revision_number":"01.02.3.065","my_number":"","lan_mac":"00:11:22:33:44:55","meid":"","fullsn":""}
  info = eregmatch( string: res, pattern: '\\{"[^\\}]+model_name":"([^"]+)"[^\\}]+\\}', icase: FALSE );
  if( res =~ "^HTTP/1\.[01] 200" && info[1] && info[1] =~ "^DWR-[0-9]+" ) {
    infos = info[0];
    detected = TRUE;
    concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
  }
}

# nb: DWR-117 seems to have "Server: Alpha_webserv", only found the Setup Page "live".
if( ! detected ) {
  url = "/login.htm";
  res = http_get_cache( port: port, item: url );
  # var str_login_desc = "... miiiCasa ... D-Link DWR-117 ..."; # nb: Localized string
  # var str_login_desc = "Welcome to D-Link DWR-117 Router with miiiCasa";
  info = eregmatch( string: res, pattern: 'var str_login_desc = ".+D-Link (DWR-[0-9]+)', icase: FALSE );
  if( res =~ "^HTTP/1\.[01] 200" && "<title>Welcome to D-Link Router Setup</title>" >< res &&
      info[1] =~ "^DWR-[0-9]+" ) {
    infos = info[1];
    detected = TRUE;
    concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
  }
}

# nb:
# - DWR-118 in turn has "Server: WebServer" which seems to have the same/similar software base like
#   D-Link DIR- devices (see gb_dlink_dir_http_detect.nasl).
# - Also DWR-9xx devices
if( ! detected ) {

  url = "/";
  res = http_get_cache( port: port, item: url );

  # <title>D-Link DWR-118</title>
  # <td><script>I18N("h", "Model Name");</script> : DWR-118</td>
  if( res =~ "^HTTP/1\.[01] 200" &&
      ( "D-Link logo" >< res || res =~ "COPYRIGHT.*D-Link" || "dlinkrouter.local" >< res || '"loginpage.htm"' >< res ) &&
      ( res =~ "<title>D-Link DWR-[0-9]+</title>" ||
        res =~ "Model Name.+DWR-[0-9]+" ) ) {
    detected = TRUE;
    concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
  }
}

if( detected ) {

  set_kb_item( name:"d-link/detected", value:TRUE );
  # nb: The new key for D-link active checks affecting multiple device types
  set_kb_item( name:"d-link/http/detected", value:TRUE );

  set_kb_item( name:"d-link/dwr/detected", value:TRUE );
  set_kb_item( name:"d-link/dwr/http/detected", value:TRUE );

  fw_version = "unknown";
  os_app     = "D-Link DWR";
  os_cpe     = "cpe:/o:dlink:dwr";
  hw_version = "unknown";
  hw_app     = "D-Link DWR";
  hw_cpe     = "cpe:/h:dlink:dwr";
  model      = "unknown";
  install    = "/";

  dev_infos = eregmatch( string: infos, pattern: "^DWR-([0-9]+)_([^_]+)_FW([0-9.]+)", icase: FALSE );
  if( dev_infos ) {
    model = dev_infos[1];
    hw_version = dev_infos[2];
    fw_version = dev_infos[3];
  }

  if( model == "unknown" ) {
    # nb: The "/js/func.js" file as well as the setup page only includes the model without fw/hw version info
    dev_infos = eregmatch( string: infos, pattern: "^DWR-([0-9]+)", icase: FALSE );
    if( dev_infos )
      model = dev_infos[1];
  }

  if( model == "unknown" ) {
    mo = eregmatch( string: infos, pattern: '"model_name":"DWR-([0-9]+)"', icase: FALSE );
    if( mo[1] )
      model = mo[1];
  }

  if( model == "unknown" ) {
    mo = eregmatch( string: res, pattern: "<title>D-Link DWR-([0-9]+)</title>", icase: FALSE );
    if( mo[1] ) {
      model = mo[1];
      # nb: Needs to be set as otherwise this info would be not available in the reporting
      info[0] = mo[0];
    }
  }

  if( fw_version == "unknown" ) {
    fw_ver = eregmatch( string: infos, pattern: '"fw_ver":"([0-9.]+)', icase: FALSE );
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
      fw_version = ereg_replace( pattern:"\.$", string:fw_version, replace:"" );
    }
  }

  if( hw_version == "unknown" ) {
    hw_ver = eregmatch( string: infos, pattern: '"hw_ver":"([^"]+)"', icase: FALSE );
    if( hw_ver[1] )
      hw_version = hw_ver[1];
  }

  # <td><script>I18N("h", "Model Name");</script> : DWR-118</td>
  # <td><script>I18N("h", "Hardware Version");</script> : B1</td>
  # <td><script>I18N("h", "Firmware Version");</script> : 2.06CP</td>
  if( model == "unknown" ) {
    mo = eregmatch( pattern: '"Model Name"\\);</script> : DWR-([0-9A-Z]+)<', string: res );
    if( mo[1] ) {
      model = mo[1];
      info[0] = mo[0];
    }
  }

  if( fw_version == "unknown" ) {
    fw_ver = eregmatch( pattern: '"Firmware Version"\\);</script> : ([0-9.]+)([a-zA-Z]*)?</td>', string: res );
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
      if( info[0] )
        info[0] += '\n' + fw_ver[0];
      else
        info[0] = fw_ver[0];
    }
  }

  if( hw_version == "unknown" ) {
    hw_ver = eregmatch( pattern: '"Hardware Version"\\);</script> : ([^<]+)</td>', string: res );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
      if( info[0] )
        info[0] += '\n' + hw_ver[0];
      else
        info[0] = hw_ver[0];
    }
  }

  if( model != "unknown" ) {
    os_app += "-" + model + " Firmware";
    os_cpe += "-" + tolower( model ) + "_firmware";
    hw_app += "-" + model + " Device";
    hw_cpe += "-" + tolower( model );
    set_kb_item( name:"d-link/dwr/model", value:model );
  } else {
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "-unknown_model";
  }

  if( fw_version != "unknown" ) {
    os_cpe += ":" + fw_version;
    set_kb_item( name:"d-link/dwr/fw_version", value:fw_version );
  }

  if( hw_version != "unknown" ) {
    hw_cpe += ":" + tolower( hw_version );
    set_kb_item( name:"d-link/dwr/hw_version", value:hw_version );
  }

  os_register_and_report( os:os_app, cpe:os_cpe, banner_type:"D-Link DWR Device Login Page", port:port, desc:"D-Link DWR Devices Detection (HTTP)", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app,
                                   version:fw_version,
                                   concluded:info[0],
                                   concludedUrl:concl_url,
                                   install:install,
                                   cpe:os_cpe );

  report += '\n\n' + build_detection_report( app:hw_app,
                                             version:hw_version,
                                             concluded:info[0],
                                             concludedUrl:concl_url,
                                             install:install,
                                             cpe:hw_cpe );

  log_message( port:port, data:report );
}

exit( 0 );
