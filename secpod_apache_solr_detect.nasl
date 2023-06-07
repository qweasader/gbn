# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903506");
  script_version("2021-12-17T10:50:06+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-12-17 10:50:06 +0000 (Fri, 17 Dec 2021)");
  script_tag(name:"creation_date", value:"2014-01-29 13:13:35 +0530 (Wed, 29 Jan 2014)");
  script_name("Apache Solr Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8983);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://lucene.apache.org/solr/");

  script_tag(name:"summary", value:"HTTP based detection of Apache Solr.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:8983 );

foreach dir( make_list_unique( "/", "/solr", "/apachesolr", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( ">Solr Admin<" >< res || "Solr admin page" >< res || 'ng-app="solrAdminApp"' >< res ) ) {

    set_kb_item( name:"apache/solr/detected", value:TRUE );
    set_kb_item( name:"apache/solr/http/detected", value:TRUE );
    version = "unknown";

    url = dir + "/admin/info/system";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    # "solr-spec-version":"8.6.1",
    # <str name="solr-spec-version">5.5.5</str>
    vers = eregmatch( pattern:'(solr-spec-version">|"solr-spec-version":")([0-9.]+)', string:res );
    if( ! isnull( vers[2] ) ) {
      version = vers[2];
      concurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( version == "unknown" ) {
      url = dir + "/#/";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      # <link rel="icon" type="image/x-icon" href="img/favicon.ico?_=8.6.1">
      # <script src="js/require.js?_=5.5.5" data-main="js/main"></script>
      vers = eregmatch( string:res, pattern:"(js/require\.js|img/favicon\.ico)\?_=([0-9.]+)", icase:TRUE );
      if( ! isnull( vers[2] ) ) {
        version = vers[2];
        concurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    # nb: This is for older 3.x (and possible 4.x) versions of Solr so
    # we keep it at the bottom for now.
    if( version == "unknown" ) {
      url = dir + "/admin/registry.jsp";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      # solr-spec-version>3.6.0
      vers = eregmatch( string:res, pattern:"solr-spec-version>([0-9.]+)", icase:TRUE );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        concurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:solr:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:solr";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Apache Solr",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0],
                                              concludedUrl:concurl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
