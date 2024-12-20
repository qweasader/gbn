# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-June/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870688");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:47:25 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2009-2625");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2011:0858-01");
  script_name("RedHat Update for xerces-j2 RHSA-2011:0858-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-j2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"xerces-j2 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The xerces-j2 packages provide the Apache Xerces2 Java Parser, a
  high-performance XML parser. A Document Type Definition (DTD) defines the
  legal syntax (and also which elements can be used) for certain types of
  files, such as XML files.

  A flaw was found in the way the Apache Xerces2 Java Parser processed the
  SYSTEM identifier in DTDs. A remote attacker could provide a
  specially-crafted XML file, which once parsed by an application using the
  Apache Xerces2 Java Parser, would lead to a denial of service (application
  hang due to excessive CPU use). (CVE-2009-2625)

  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. Applications using the Apache Xerces2 Java
  Parser must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.7.1~12.6.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-debuginfo", rpm:"xerces-j2-debuginfo~2.7.1~12.6.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
