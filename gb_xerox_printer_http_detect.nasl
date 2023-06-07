# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103648");
  script_version("2022-05-13T07:00:26+0000");
  script_tag(name:"last_modification", value:"2022-05-13 07:00:26 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2013-01-30 14:31:24 +0100 (Wed, 30 Jan 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Xerox Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Xerox printer devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("xerox_printers.inc");
include("dump.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

urls = get_xerox_detect_urls();

foreach url (keys(urls)) {

  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  buf = http_get_cache(item: url, port: port);
  if(!buf || (buf !~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 401"))
    continue;

  # Replace non-printable characters to avoid language based false-negatives
  buf = bin2string(ddata: buf, noprint_replacement: "");

  if (match = eregmatch(pattern: pattern, string: buf, icase: TRUE)) {

    if (isnull(match[1]))
      continue;

    concl = "    " + match[0];
    conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    if ("signatureText1" >< pattern) {
      mod = split(match[1], sep: " ", keep: TRUE);
      model = chomp(mod[0]);
      # Replace things like (tm)
      model = str_replace(string: model, find: "(tm)", replace: "");
      # For strings like 'Xerox\xae 700 Digital Color Press Ver. 72.91.31.8'
      if (model == "")
        model = chomp(mod[1]);
      else
        if (mod[1] =~ "^[0-9]")
          model += " " + chomp(mod[1]);
    } else if ("Xerox Asset Tag" >< pattern) {
      url = "/ssm/Management/Anonymous/StatusConfig";
      headers = make_array("Content-Type", "text/xml;",
                           "soapAction", "http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig#GetAttribute",
                           "X-Requested-With", "XMLHttpRequest");
      data = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
             '<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
             '<msg:MessageInformation xmlns:msg="http://www.fujixerox.co.jp/2014/08/ssm/management/message">' +
             '<msg:MessageExchangeType>RequestResponse</msg:MessageExchangeType>' +
             '<msg:MessageType>Request</msg:MessageType><msg:Action>http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig#GetAttribute</msg:Action>' +
             '<msg:From><msg:Address>http://www.fujixerox.co.jp/2014/08/ssm/management/soap/epr/client</msg:Address><msg:ReferenceParameters/>' +
             '</msg:From></msg:MessageInformation></soap:Header>' +
             '<soap:Body><cfg:GetAttribute xmlns:cfg="http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig">' +
             '<cfg:Object name="urn:fujixerox:names:ssm:1.0:management:ProductName" offset="0"/>' +
             '</cfg:GetAttribute></soap:Body></soap:Envelope>';
      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: "/home/index.html");
      # nb: Don't use http_keepalive_send_recv() since we get a nested response
      res = http_send_recv(port: port, data: req);
      # <Attribute name="TradeName" type="string" xml:space="preserve">Xerox Phaser 6510DN Printer</Attribute>
      res = bin2string(ddata: res, noprint_replacement: "");
      mod = eregmatch(pattern: '"TradeName"[^>]+>Xerox ([^<]+)', string:res);
      if (!isnull(mod[1])) {
        concl += '\n    ' + mod[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        model = mod[1];
        model = str_replace(string: model, find: " Printer", replace: "");
      }
    } else if ('"name">DC-' >< pattern) {
      # <td align="left" valign="middle" class="name">DC-260-D44DB8</td>
      model = "DocuColor " + match[1];
    } else {

      # nb: One example:
      # <TD id = "productName">
      # Xerox D136 Copier-Printer
      # </TD>
      model = chomp(match[1]);
      if(!isnull(match[2]))
        model += " " + chomp(match[2]);
    }

    set_kb_item(name: "xerox/printer/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/port", value: port);
    set_kb_item(name: "xerox/printer/http/" + port + "/model", value: model);

    # AltaLink
    # <tr ><td>Device Software:</td><td>100.002.008.05702</td></tr>
    vers = eregmatch(pattern: "Device Software:</td><td>([0-9.]+)<", string: buf);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    # DocuPrint
    # Version</td><td class=std_2>201210101131</td></tr>
    vers = eregmatch(pattern: "Version</td><td class=std_2>([0-9]+)<", string: buf);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    # <h1 class="signatureText1">Xerox D136 Copier/Printer Ver. 93.E2.21CB.86</h1>
    # <h1 class="signatureText1">Sistema Xerox Nuvera 314 EA Perfecting Production System Ver. 73.H3.72.8</h1>
    vers = eregmatch(pattern: "Ver\. ([0-9A-Z.]+)</h1>", string: buf);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    # ColorQube 8700/8900
    # System Software:</td><td>072.162.004.09100</td></tr>
    url = "/properties/configuration.php?tab=Status#heading2";
    res = http_get_cache(port: port, item: url);
    vers = eregmatch(pattern: "System Software:</td><td>([0-9.]+)<", string: res);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    # ColorQube
    # <td>System Version</td>
    # <td>1.3.8.P</td>
    url = "/aboutprinter.html";
    res = http_get_cache(port: port, item: url);
    vers = eregmatch(pattern: "System Version</td>[^<]+<td>([^<]+)</td>", string: res);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    # AltaLink C8055
    # td>Device Software Version:</td><td>103.002.011.14100</td></tr>
    url = "/properties/configuration.php?tab=Status";
    res = http_get_cache(port: port, item: url);
    vers = eregmatch(pattern: ">Device Software Version:</td><td>([^<]+)</td>", string: res);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    # Phaser 6510DN
    # <Attribute name="Version" type="string">1.30.6</Attribute>
    url = "/ssm/Management/Anonymous/StatusConfig";
    headers = make_array("Content-Type", "text/xml;",
                         "soapAction", "http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig#GetAttribute",
                         "X-Requested-With", "XMLHttpRequest");
    data = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
           '<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
           '<msg:MessageInformation xmlns:msg="http://www.fujixerox.co.jp/2014/08/ssm/management/message"><msg:MessageExchangeType>RequestResponse</msg:MessageExchangeType>' +
           '<msg:MessageType>Request</msg:MessageType><msg:Action>http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig#GetAttribute</msg:Action>' +
           '<msg:From><msg:Address>http://www.fujixerox.co.jp/2014/08/ssm/management/soap/epr/client</msg:Address><msg:ReferenceParameters/></msg:From>' +
           '</msg:MessageInformation></soap:Header>' +
           '<soap:Body><cfg:GetAttribute xmlns:cfg="http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig">' +
           '<cfg:Object name="urn:fujixerox:names:ssm:1.0:management:root" offset="0"/>' +
           '</cfg:GetAttribute></soap:Body></soap:Envelope>';
    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: "/home/index.html");
    # nb: Don't use http_keepalive_send_recv() since we get a nested response
    res = http_send_recv(port: port, data: req);
    vers = eregmatch(pattern: '<Attribute name="Version" type="string">([0-9.]+)<', string: res);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    url = "/properties/configuration.dhtml";
    res = http_get_cache(port: port, item: url);
    # System: </td> <td class="attributeDescriptor50"> 35.013.01.000 </td>
    vers = eregmatch(pattern: "System:[^>]+>[^>]+>[^0-9]+([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      concl += '\n    ' + vers[0];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);
      exit(0);
    }

    set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
    set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);

    exit(0);
  }

  else if(buf =~ "^HTTP/1\.[01] 401" && found = eregmatch(string: buf, pattern: "CentreWare Internet Services", icase: FALSE))  {

    concl = "    " + chomp(found[0]);
    conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "xerox/printer/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/port", value: port);
    set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: concl);
    set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: conclUrl);

    exit(0);
  }
}

exit(0);
