# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015833.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880947");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0436");
  script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304",
                "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308",
                "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
  script_name("CentOS Update for firefox CESA-2009:0436 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"firefox on CentOS 4");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code as the user running Firefox.
  (CVE-2009-1302, CVE-2009-1303, CVE-2009-1304, CVE-2009-1305)

  Several flaws were found in the way malformed web content was processed. A
  web page containing malicious content could execute arbitrary JavaScript in
  the context of the site, possibly presenting misleading data to a user, or
  stealing sensitive information such as login credentials. (CVE-2009-0652,
  CVE-2009-1306, CVE-2009-1307, CVE-2009-1308, CVE-2009-1309, CVE-2009-1310,
  CVE-2009-1312)

  A flaw was found in the way Firefox saved certain web pages to a local
  file. If a user saved the inner frame of a web page containing POST data,
  the POST data could be revealed to the inner frame, possibly surrendering
  sensitive information such as login credentials. (CVE-2009-1311)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.9. You can find a link to the Mozilla advisories
  in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.9, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.9~1.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
