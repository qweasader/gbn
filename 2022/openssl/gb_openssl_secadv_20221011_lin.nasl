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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104353");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-10-12 10:01:45 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 16:00:00 +0000 (Thu, 13 Oct 2022)");

  script_cve_id("CVE-2022-3358");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Using a Custom Cipher with NID_undef may lead to NULL encryption (CVE-2022-3358) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL supports creating a custom cipher via the legacy
  EVP_CIPHER_meth_new() function and associated function calls. This function was deprecated in
  OpenSSL 3.0 and application authors are instead encouraged to use the new provider mechanism in
  order to implement custom ciphers.

  OpenSSL versions 3.0.0 to 3.0.5 incorrectly handle legacy custom ciphers passed to the
  EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() and EVP_CipherInit_ex2() functions (as well as other
  similarly named encryption and decryption initialisation functions). Instead of using the custom
  cipher directly it incorrectly tries to fetch an equivalent cipher from the available providers.
  An equivalent cipher is found based on the NID passed to EVP_CIPHER_meth_new(). This NID is
  supposed to represent the unique NID for a given cipher. However it is possible for an application
  to incorrectly pass NID_undef as this value in the call to EVP_CIPHER_meth_new(). When NID_undef
  is used in this way the OpenSSL encryption/decryption initialisation function will match the NULL
  cipher as being equivalent and will fetch this from the available providers. This will succeed if
  the default provider has been loaded (or if a third party provider has been loaded that offers
  this cipher). Using the NULL cipher means that the plaintext is emitted as the ciphertext.

  Applications are only affected by this issue if they call EVP_CIPHER_meth_new() using NID_undef
  and subsequently use it in a call to an encryption/decryption initialisation function.
  Applications that only use SSL/TLS are not impacted by this issue.");

  script_tag(name:"affected", value:"OpenSSL versions 3.0.0 through 3.0.5.");

  script_tag(name:"solution", value:"Update to version 3.0.6 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20221011.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
