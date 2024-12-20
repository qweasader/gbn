# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70764");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3245", "CVE-2009-4355", "CVE-2010-0433", "CVE-2010-0740", "CVE-2010-0742", "CVE-2010-1633", "CVE-2010-2939", "CVE-2010-3864", "CVE-2010-4180", "CVE-2010-4252", "CVE-2011-0014", "CVE-2011-3207", "CVE-2011-3210");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:38 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201110-01 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in OpenSSL, allowing for the
    execution of arbitrary code and other attacks.");
  script_tag(name:"solution", value:"All OpenSSL users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.0e'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since September 17, 2011. It is likely that your system is
      already no longer affected by most of these issues.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=303739");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=308011");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=322575");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=332027");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=345767");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=347623");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=354139");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=382069");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201110-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-libs/openssl", unaffected: make_list("ge 1.0.0e", "rge 0.9.8r"), vulnerable: make_list("lt 1.0.0e"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
