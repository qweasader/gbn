# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108555");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2019-1559");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 19:47:00 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"creation_date", value:"2019-02-27 07:48:22 +0100 (Wed, 27 Feb 2019)");
  script_name("OpenSSL: 0-byte record padding oracle (CVE-2019-1559) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20190226.txt");
  script_xref(name:"URL", value:"https://github.com/RUB-NDS/TLS-Padding-Oracles#openssl-cve-2019-1559");

  script_tag(name:"summary", value:"OpenSSL is prone to a padding oracle attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an application encounters a fatal protocol error and then calls
  SSL_shutdown() twice (once to send a close_notify, and once to receive one) then OpenSSL can respond
  differently to the calling application if a 0 byte record is received with invalid padding compared
  to if a 0 byte record is received with an invalid MAC.");

  script_tag(name:"impact", value:"If the application then behaves differently based on that in a way that
  is detectable to the remote peer, then this amounts to a padding oracle that could be used to decrypt data.

  In order for this to be exploitable 'non-stitched' ciphersuites must be in use. Stitched ciphersuites
  are optimised implementations of certain commonly used ciphersuites. Also the application must call
  SSL_shutdown() twice even if a protocol error has occurred (applications should not do this but some
  do anyway). AEAD ciphersuites are not impacted.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2-1.0.2q.

  This issue does not impact OpenSSL 1.1.1 or 1.1.0.");

  script_tag(name:"solution", value:"Upgrade OpenSSL to version 1.0.2r or later. See the references for more details.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"1.0.2", test_version2:"1.0.2q" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2r", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
