# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121381");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:51 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201506-04");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Chromium. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201506-04");
  script_cve_id("CVE-2015-1233", "CVE-2015-1234", "CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1243", "CVE-2015-1244", "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248", "CVE-2015-1250", "CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1262", "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201506-04");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 43.0.2357.65"), vulnerable: make_list("lt 43.0.2357.65"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
