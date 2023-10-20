# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72458");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868", "CVE-2012-2143", "CVE-2012-2655", "CVE-2012-3488", "CVE-2012-3489");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-03 11:11:28 -0400 (Wed, 03 Oct 2012)");
  script_name("Gentoo Security Advisory GLSA 201209-24 (PostgreSQL)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in PostgreSQL which may
    allow a remote attacker to conduct several attacks.");
  script_tag(name:"solution", value:"All PostgreSQL 9.1 server users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.1.5'


All PostgreSQL 9.0 server users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.0.9'


All PostgreSQL 8.4 server users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-8.4.13'


All PostgreSQL 8.3 server users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose
'>=dev-db/postgresql-server-8.3.20'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-24");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=406037");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=419727");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=431766");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201209-24.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-db/postgresql-server", unaffected: make_list("ge 9.1.5", "rge 9.0.9", "rge 8.4.13", "rge 8.3.20"), vulnerable: make_list("lt 9.1.5"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
