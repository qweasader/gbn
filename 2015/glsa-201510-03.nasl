# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121416");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"creation_date", value:"2015-11-08 13:04:37 +0200 (Sun, 08 Nov 2015)");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_name("Gentoo Security Advisory GLSA 201510-03");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Wireshark. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201510-03");
  script_cve_id("CVE-2015-2187", "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2190", "CVE-2015-2191", "CVE-2015-2192", "CVE-2015-3182", "CVE-2015-3808", "CVE-2015-3809", "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-3814", "CVE-2015-3815", "CVE-2015-3906", "CVE-2015-4651", "CVE-2015-4652");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201510-03");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"net-analyzer/wireshark", unaffected: make_list("ge 1.12.7"), vulnerable: make_list("lt 1.12.7"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
