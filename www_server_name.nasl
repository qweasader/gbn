# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11239");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Hidden WWW Server Name (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"It seems that the remote web server tries to hide its
  version or name.

  However, using a special crafted request, the scanner was able to discover it.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

s = http_open_socket(port);
if(! s) exit(0);

r = http_get(port: port, item: "/");
send(socket: s, data: r);

r = http_recv_headers2(socket:s);
http_close_socket(s);

# If anybody can get the server name, exit
srv = string("^Server: *[^ \t\n\r]");
if (egrep(string: r, pattern: srv)) exit(0);

i = 0;
req[i] = string("HELP\r\n\r\n"); i=i+1;
req[i] = string("HEAD / \r\n\r\n"); i=i+1;
req[i] = string("HEAD / HTTP/1.0\r\n\r\n"); i=i+1;
req[i] = string("HEAD / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n"); i=i+1;

for (i = 0; req[i]; i=i+1)
{
  s = http_open_socket(port);
  if (s)
  {
    send(socket: s, data: req[i]);
    r = http_recv_headers2(socket:s);
    http_close_socket(s);
    if (strlen(r) && (s1 = egrep(string: r, pattern: srv)))
    {
      s1 -= '\r\n'; s1 -= 'Server:';
      rep = "
It seems that the remote server tries to hide its version
or name.
However, using a special crafted request, the scanner was able
to determine that it is running :
" + s1 + "

Solution: Fix your configuration.";

      log_message(port:port, data:rep);
      # We check before: creating a list is not a good idea
      sb = string("www/banner/", port);
      if (! get_kb_item(sb))
      {
        replace_kb_item(name: sb, value: r);
      }
      else
      {
        sb = string("www/alt-banner/", port);
        if (! get_kb_item(sb))
          set_kb_item(name: sb, value: r);
      }
      exit(0);
    }
  }
}
