# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016412.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880625");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2010:0002");
  script_cve_id("CVE-2009-3720");
  script_name("CentOS Update for PyXML CESA-2010:0002 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'PyXML'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"PyXML on CentOS 5");
  script_tag(name:"insight", value:"PyXML provides XML libraries for Python. The distribution contains a
  validating XML parser, an implementation of the SAX and DOM programming
  interfaces, and an interface to the Expat parser.

  A buffer over-read flaw was found in the way PyXML's Expat parser handled
  malformed UTF-8 sequences when processing XML files. A specially-crafted
  XML file could cause Python applications using PyXML's Expat parser to
  crash while parsing the file. (CVE-2009-3720)

  This update makes PyXML use the system Expat library rather than its own
  internal copy. Therefore, users must install the RHSA-2009:1625 expat
  update together with this PyXML update to resolve the CVE-2009-3720 issue.

  All PyXML users should upgrade to this updated package, which changes PyXML
  to use the system Expat library. After installing this update along with
  RHSA-2009:1625, applications using the PyXML library must be restarted for
  the update to take effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"PyXML", rpm:"PyXML~0.8.4~4.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
