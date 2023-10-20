# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170366");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 21:10:29 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-08 20:11:00 +0000 (Mon, 08 May 2023)");

  script_cve_id("CVE-2023-26063", "CVE-2023-26064", "CVE-2023-26065", "CVE-2023-26066");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer Multiple Postscript Interpreter Vulnerabilities (Mar 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to multiple vulnerabilities
  in the Postscript interpreter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist in the Postscript interpreter:

  - CVE-2023-26063: Type confusion vulnerability

  - CVE-2023-26064: Out of bounds write vulnerability

  - CVE-2023-26065: Integer overflow vulnerability

  - CVE-2023-26066: Improper validation of the stack");

  script_tag(name:"impact", value:"These vulnerabilities can be leveraged by an attacker to execute
  arbitrary code.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-26063.pdf");
  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-26064.pdf");
  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-26065.pdf");
  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-26066.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!version = toupper(get_app_version(cpe: cpe, port: port, nofork: TRUE)))
  exit(0);

if (cpe =~ "^cpe:/o:lexmark:cx93[01]" || cpe =~ "^cpe:/o:lexmark:cx94[234]" ||
    cpe =~ "^cpe:/o:lexmark:xc9335" || cpe =~ "^cpe:/o:lexmark:xc94[456]5") {
  if (version_is_less_equal(version: version, test_version: "CXTPC.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs943") {
  if (version_is_less_equal(version: version, test_version: "CSTPC.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx432" || cpe =~ "^cpe:/o:lexmark:xm3142") {
  if (version_is_less_equal(version: version, test_version: "MXTCT.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx931") {
  if (version_is_less_equal(version: version, test_version: "MXTPM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx73[05]" || cpe =~ "^cpe:/o:lexmark:xc43[45]2") {
  if (version_is_less_equal(version: version, test_version: "CXTMM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs73[05]" || cpe =~ "^cpe:/o:lexmark:c43[45]2") {
  if (version_is_less_equal(version: version, test_version: "CSTMM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:b2236") {
  if (version_is_less_equal(version: version, test_version: "MSLSG.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_is_less_equal(version: version, test_version: "MXLSG.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]31" || cpe =~ "^cpe:/o:lexmark:m1342" ||
    cpe =~ "^cpe:/o:lexmark:b3442" || cpe =~ "^cpe:/o:lexmark:b3340"||
    cpe =~ "^cpe:/o:lexmark:xm1342") {
  if (version_is_less_equal(version: version, test_version: "MSLBD.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[34]31" || cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_is_less_equal(version: version, test_version: "MXLBD.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[3456]21" || cpe =~ "^cpe:/o:lexmark:m124[26]" ||
    cpe =~ "^cpe:/o:lexmark:b2338" || cpe =~ "^cpe:/o:lexmark:b2442" ||
    cpe =~ "^cpe:/o:lexmark:b2546" || cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_is_less_equal(version: version, test_version: "MSNGM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms622" || cpe =~ "^cpe:/o:lexmark:m3250") {
  if (version_is_less_equal(version: version, test_version: "MSTGM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_is_less_equal(version: version, test_version: "MXNGM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2442" || cpe =~ "^cpe:/o:lexmark:mb2546" ||
    cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_is_less_equal(version: version, test_version: "MXTGM.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[78]25" || cpe =~ "^cpe:/o:lexmark:ms82[13]" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_is_less_equal(version: version, test_version: "MSNGW.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[26]" || cpe =~ "^cpe:/o:lexmark:m5255" ||
    cpe =~ "^cpe:/o:lexmark:m5270") {
  if (version_is_less_equal(version: version, test_version: "MSTGW.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[12]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm5365" || cpe =~ "^cpe:/o:lexmark:xm73(55|70)" ||
    cpe =~ "^cpe:/o:lexmark:mb2770") {
  if (version_is_less_equal(version: version, test_version: "MXTGW.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs43[19]") {
  if (version_is_less_equal(version: version, test_version: "CSLBN.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_is_less_equal(version: version, test_version: "CSLBL.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c2326") {
  if (version_is_less_equal(version: version, test_version: "CSLBN.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431" ||
    cpe =~ "^cpe:/o:lexmark:xc2326") {
  if (version_is_less_equal(version: version, test_version: "CXLBN.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3224" || cpe =~ "^cpe:/o:lexmark:mc3326" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_is_less_equal(version: version, test_version: "CXLBL.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_is_less_equal(version: version, test_version: "CSTZJ.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2[34]25" ||
    cpe =~ "^cpe:/o:lexmark:c2535") {
  if (version_is_less_equal(version: version, test_version: "CSNZJ.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_is_less_equal(version: version, test_version: "CXTZJ.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_is_less_equal(version: version, test_version: "CXNZJ.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[057]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc615[23]" || cpe =~ "^cpe:/o:lexmark:xc81(55|60|63)") {
  if (version_is_less_equal(version: version, test_version: "CXTPP.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs82[07]" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_is_less_equal(version: version, test_version: "CSTPP.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[0578]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_is_less_equal(version: version, test_version: "CSTAT.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx72[57]" || cpe =~ "^cpe:/o:lexmark:xc41(40|43|50|53)") {
  if (version_is_less_equal(version: version, test_version: "CXTAT.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[137]" || cpe =~ "^cpe:/o:lexmark:c9235") {
  if (version_is_less_equal(version: version, test_version: "CSTMH.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[01234]" || cpe =~ "^cpe:/o:lexmark:xc92[23456]5") {
  if (version_is_less_equal(version: version, test_version: "CXTMH.081.231")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.081.232");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# nb: changed order so m1140+ is checked before m1140
if (cpe =~ "^cpe:/o:lexmark:ms51[07]" || cpe =~ "^cpe:/o:lexmark:ms610dn" ||
    cpe =~ "^cpe:/o:lexmark:ms617" || cpe =~ "^cpe:/o:lexmark:m1140+" ||
    cpe =~ "^cpe:/o:lexmark:m1145" || cpe =~ "^cpe:/o:lexmark:m3150dn") {
  if (version_is_less_equal(version: version, test_version: "LW80.PR2.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PR2.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms31[027]" || cpe =~ "^cpe:/o:lexmark:ms410" ||
    cpe =~ "^cpe:/o:lexmark:m1140") {
  if (version_is_less_equal(version: version, test_version: "LW80.PRL.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PRL.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms315" || cpe =~ "^cpe:/o:lexmark:ms41[57]") {
  if (version_is_less_equal(version: version, test_version: "LW80.TL2.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.TL2.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms610de" || cpe =~ "^cpe:/o:lexmark:m3150de") {
  if (version_is_less_equal(version: version, test_version: "LW80.PR4.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PR4.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx31[07]" || cpe =~ "^cpe:/o:lexmark:xm1135") {
  if (version_is_less_equal(version: version, test_version: "LW80.SB2.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB2.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx41[07]" || cpe =~ "^cpe:/o:lexmark:mx51[017]" ||
    cpe =~ "^cpe:/o:lexmark:xm114[05]") {
  if (version_is_less_equal(version: version, test_version: "LW80.SB4.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB4.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx61[017]" || cpe =~ "^cpe:/o:lexmark:xm3150") {
  if (version_is_less_equal(version: version, test_version: "LW80.SB7.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB7.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms71[01]" || cpe =~ "^cpe:/o:lexmark:ms810dn" ||
    cpe =~ "^cpe:/o:lexmark:ms81[178]" || cpe =~ "^cpe:/o:lexmark:ms812dn" ||
    cpe =~ "^cpe:/o:lexmark:m5163dn") {
  if (version_is_less_equal(version: version, test_version: "LW80.DN2.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.DN2.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms810de" || cpe =~ "^cpe:/o:lexmark:m5155" ||
    cpe =~ "^cpe:/o:lexmark:m5163de") {
  if (version_is_less_equal(version: version, test_version: "LW80.DN4.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.DN4.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms812de" || cpe =~ "^cpe:/o:lexmark:m5170") {
  if (version_is_less_equal(version: version, test_version: "LW80.DN7.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.DN7.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx71[0178]" || cpe =~ "^cpe:/o:lexmark:mx81[012]" ||
    cpe =~ "^cpe:/o:lexmark:xm[57][12](63|70)" || cpe =~ "^cpe:/o:lexmark:xm7155") {
  if (version_is_less_equal(version: version, test_version: "LW80.TU.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.TU.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms911") {
  if (version_is_less_equal(version: version, test_version: "LW80.SA.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SA.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx91[012]" || cpe =~ "^cpe:/o:lexmark:xm91[456]5") {
  if (version_is_less_equal(version: version, test_version: "LW80.MG.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.MG.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx6500e") {
  if (version_is_less_equal(version: version, test_version: "LW80.JD.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.JD.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs31[07]") {
  if (version_is_less_equal(version: version, test_version: "LW80.VYL.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VYL.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs41[07]") {
  if (version_is_less_equal(version: version, test_version: "LW80.VY2.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VY2.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs51[07]" || cpe =~ "^cpe:/o:lexmark:c2132") {
  if (version_is_less_equal(version: version, test_version: "LW80.VY4.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VY4.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx31[07]") {
  if (version_is_less_equal(version: version, test_version: "LW80.GM2.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM2.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx41[07]" || cpe =~ "^cpe:/o:lexmark:xc2130") {
  if (version_is_less_equal(version: version, test_version: "LW80.GM4.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM4.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx51[07]" || cpe =~ "^cpe:/o:lexmark:xc2132") {
  if (version_is_less_equal(version: version, test_version: "LW80.GM7.P233")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM7.P234");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c746") {
  if (version_is_less_equal(version: version, test_version: "LHS60.CM2.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.CM2.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c748" || cpe =~ "^cpe:/o:lexmark:cs748") {
  if (version_is_less_equal(version: version, test_version: "LHS60.CM4.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.CM4.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c792" || cpe =~ "^cpe:/o:lexmark:cs796") {
  if (version_is_less_equal(version: version, test_version: "LHS60.HC.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HC.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c925") {
  if (version_is_less_equal(version: version, test_version: "LHS60.HV.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HV.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c950") {
  if (version_is_less_equal(version: version, test_version: "LHS60.TP.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.TP.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x548" || cpe =~ "^cpe:/o:lexmark:xs548") {
  if (version_is_less_equal(version: version, test_version: "LHS60.VK.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.VK.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x74[68]" || cpe =~ "^cpe:/o:lexmark:xs748") {
  if (version_is_less_equal(version: version, test_version: "LHS60.NY.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.NY.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x79[25]" || cpe =~ "^cpe:/o:lexmark:xs79[68]") {
  if (version_is_less_equal(version: version, test_version: "LHS60.MR.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.MR.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x925" || cpe =~ "^cpe:/o:lexmark:xs925") {
  if (version_is_less_equal(version: version, test_version: "LHS60.HK.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HK.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x95[024]" || cpe =~ "^cpe:/o:lexmark:xs95[05]") {
  if (version_is_less_equal(version: version, test_version: "LHS60.TQ.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.TQ.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:6500e") {
  if (version_is_less_equal(version: version, test_version: "LHS60.JR.P759")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.JR.P760");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c734") {
  if (version_is_less_equal(version: version, test_version: "LR.SK.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.SK.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c736") {
  if (version_is_less_equal(version: version, test_version: "LR.SKE.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.SKE.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:e46") {
  if (version_is_less_equal(version: version, test_version: "LR.LBH.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.LBH.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:t65") {
  if (version_is_less_equal(version: version, test_version: "LR.JP.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.JP.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x46") {
  if (version_is_less_equal(version: version, test_version: "LR.BS.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.BS.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x65") {
  if (version_is_less_equal(version: version, test_version: "LR.MN.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.MN.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x73") {
  if (version_is_less_equal(version: version, test_version: "LR.FL.P837")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.FL.P838");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:w850") {
  if (version_is_less_equal(version: version, test_version: "LP.JB.P836")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LP.JB.P837");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x86") {
  if (version_is_less_equal(version: version, test_version: "LP.SP.P836")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LP.SP.P837");
    security_message(port: 0, data: report);
    exit(0);
  }
}


exit(99);
