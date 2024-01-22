# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100439");
  script_version("2023-12-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-12-05 05:06:18 +0000 (Tue, 05 Dec 2023)");
  # nb: This was initially a single VT which got split into multiple later. As we covered all flaws
  # at this time the original creation_date has been kept in all later created VTs.
  script_tag(name:"creation_date", value:"2023-10-20 08:47:30 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod", value:"70"); # remote_banner is too high but remote_banner_unreliable too low...

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Squid Multiple 0-Day Vulnerabilities (Oct 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to multiple zero-day (0-day) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws have been reported in 2021 to the vendor and
  seems to be not fixed yet:

  - X-Forwarded-For Stack Overflow

  - Chunked Encoding Stack Overflow

  - Use-After-Free in Cache Manager Errors

  - Memory Leak in HTTP Response Parsing

  - Memory Leak in ESI Error Processing

  - One-Byte Buffer OverRead in HTTP Request Header Parsing

  - strlen(NULL) Crash Using Digest Authentication GHSA-254c-93q9-cp53

  - Assertion in ESI Header Handling

  - Gopher Assertion Crash

  - Whois Assertion Crash

  - RFC 2141 / 2169 (URN) Assertion Crash

  - Assertion in Negotiate/NTLM Authentication Using Pipeline Prefetching

  - Assertion on IPv6 Host Requests with --disable-ipv6

  - Assertion Crash on Unexpected 'HTTP/1.1 100 Continue' Response Header

  - Pipeline Prefetch Assertion With Double 'Expect:100-continue' Request Headers

  - Pipeline Prefetch Assertion With Invalid Headers

  - Assertion Crash in Deferred Requests

  - Assertion in Digest Authentication

  - FTP Authentication Crash

  - Assertion Crash In HTTP Response Headers Handling

  - Implicit Assertion in Stream Handling

  - Use-After-Free in ESI 'Try' (and 'Choose') Processing

  - Use-After-Free in ESI Expression Evaluation

  - Buffer Underflow in ESI GHSA-wgvf-q977-9xjg

  - Assertion Due to 0 ESI 'when' Checking GHSA-4g88-277m-q89r

  - Assertion Using ESI's When Directive GHSA-4g88-277m-q89r

  - Assertion in ESI Variable Assignment (String)

  - Assertion in ESI Variable Assignment

  - Null Pointer Dereference In ESI's esi:include and esi:when

  Note: Various GHSA advisories have been provided by the security researcher but are not published
  / available yet.");

  script_tag(name:"affected", value:"As of 10/2023 the situation about affected versions is
  largely unclear (The security researcher only stated that all vulnerabilities were discovered
  in squid-5.0.5 and the vendor only published a few advisories so far).

  Due to this unclear situation all Squid versions are currently assumed to be vulnerable by the not
  yet fixed flaws.");

  script_tag(name:"solution", value:"No known solution is available as of 23th October, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/");
  script_xref(name:"URL", value:"https://joshua.hu/squid-security-audit-35-0days-45-exploits");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/11/3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos["version"];
if (!version)
  version = "unknown";

location = infos["location"];

report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
security_message(port: port, data: report);
exit(0);
