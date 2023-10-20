# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100302");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PHP Live! Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of PHP Live!.");

  script_xref(name:"URL", value:"http://www.phplivesupport.com");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "PHP Live! Detection";

port = http_get_port(default: 80);
if(!http_can_host_php(port: port)) exit(0);

foreach dir(make_list_unique("/phplive", "/support", http_cgi_dirs(port: port))) {

  install = dir;
  if(dir == "/") dir = "";
  url = dir + "/index.php";
  buf = http_get_cache(item: url, port: port);
  if(!buf) continue;

  if(egrep(pattern: "Powered by <a [^>]+>PHP [<i>]*Live!", string: buf, icase: TRUE)) {
    vers = "unknown";
    version = eregmatch(string: buf, pattern: "v([0-9.]+)", icase: TRUE);
    if(version[1])
      vers = chomp(version[1]);

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/phplive"), value: tmp_version);
    set_kb_item(name: "phplive/detected", value: TRUE);

    cpe = build_cpe(value: tmp_version, exp: "^([0-9.]+)", base: "cpe:/a:phplivesupport.:phplive:");
    if(!isnull(cpe))
      register_host_detail(name: "App", value: cpe, desc: SCRIPT_DESC);

    info = string("PHP Live! Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port: port, data: info);
    exit(0);
  }
}

exit(0);
