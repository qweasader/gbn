# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"affected", value:"axis on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Apache Axis is an implementation of SOAP (Simple Object Access Protocol).
  It can be used to build both web service clients and servers.

  Apache Axis did not verify that the server hostname matched the domain name
  in the subject's Common Name (CN) or subjectAltName field in X.509
  certificates. This could allow a man-in-the-middle attacker to spoof an SSL
  server if they had a certificate that was valid for any domain name.
  (CVE-2012-5784)

  All users of axis are advised to upgrade to these updated packages, which
  correct this issue. Applications using Apache Axis must be restarted for
  this update to take effect.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00030.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56408");
  script_oid("1.3.6.1.4.1.25623.1.0.870933");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-22 10:02:17 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-5784");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:0269-01");
  script_name("RedHat Update for axis RHSA-2013:0269-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'axis'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"axis", rpm:"axis~1.2.1~7.3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
