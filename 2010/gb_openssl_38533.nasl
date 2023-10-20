# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100588");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-20 13:41:39 +0200 (Tue, 20 Apr 2010)");
  script_cve_id("CVE-2010-0433");

  script_name("OpenSSL 'dtls1_retrieve_buffered_fragment()' Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38533");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=567711");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=569774");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/03/03/5");
  script_xref(name:"URL", value:"http://cvs.openssl.org/chngview?cn=19374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510726");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_openssl_consolidation.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial-of-service vulnerability caused
  by a NULL-pointer dereference.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"OpenSSL versions 0.9.8m and prior are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^0\.9\." && version_is_less(version:vers, test_version:"0.9.8n")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8n", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
