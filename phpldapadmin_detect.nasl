###############################################################################
# OpenVAS Vulnerability Test
#
# phpLDAPadmin Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100395");
  script_version("2020-11-10T06:17:23+0000");
  script_tag(name:"last_modification", value:"2020-11-10 06:17:23 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("phpLDAPadmin Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://phpldapadmin.sourceforge.net/");

  script_tag(name:"summary", value:"HTTP based detection of phpLDAPadmin.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/phpldapadmin", "/ldapadmin", "/ldap", "/phpldapadmin/htdocs", "/ldapadmin/htdocs", "/htdocs", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache(item:url, port:port);
  if(!buf)
    continue;

  if("<title>phpLDAPadmin" >< buf && ("phpLDAPadmin logo" >< buf || 'src="tree.php"' >< buf || 'src="welcome.php"' >< buf)) {

    version = "unknown";
    conclurl = http_report_vuln_url(port:port, url:url, url_only:TRUE);

    # <title>phpLDAPadmin (1.2.2) - </title>
    vers = eregmatch(string:buf, pattern:"phpLDAPadmin \(([0-9.]+)\)", icase:TRUE);
    if(vers[1])
      version = vers[1];

    if(version == "unknown") {
      # <title>phpLDAPadmin - 0.9.5
      vers = eregmatch(string:buf, pattern:"<title>phpLDAPadmin - ([0-9.]+)", icase:TRUE);
      if(vers[1])
        version = vers[1];
    }

    set_kb_item(name:"www/" + port + "/phpldapadmin", value:string(version, " under ", install));
    set_kb_item(name:"phpldapadmin/installed", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:phpldapadmin_project:phpldapadmin:");
    if(!cpe)
      cpe = "cpe:/a:phpldapadmin_project:phpldapadmin";

    register_product(cpe:cpe, location:install, port:port, service:"www");
    log_message(data:build_detection_report(app:"phpLDAPadmin",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclurl,
                                            concluded:vers[0]),
                port:port);
  }
}

exit(0);
