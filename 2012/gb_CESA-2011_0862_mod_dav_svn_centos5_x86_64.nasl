# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-June/017613.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881360");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:35:26 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2011:0862");
  script_name("CentOS Update for mod_dav_svn CESA-2011:0862 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_dav_svn'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mod_dav_svn on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Subversion (SVN) is a concurrent version control system which enables one
  or more users to collaborate in developing and maintaining a hierarchy of
  files and directories while keeping a history of all changes. The
  mod_dav_svn module is used with the Apache HTTP Server to allow access to
  Subversion repositories via HTTP.

  An infinite loop flaw was found in the way the mod_dav_svn module processed
  certain data sets. If the SVNPathAuthz directive was set to
  'short_circuit', and path-based access control for files and directories
  was enabled, a malicious, remote user could use this flaw to cause the
  httpd process serving the request to consume an excessive amount of system
  memory. (CVE-2011-1783)

  A NULL pointer dereference flaw was found in the way the mod_dav_svn module
  processed requests submitted against the URL of a baselined resource. A
  malicious, remote user could use this flaw to cause the httpd process
  serving the request to crash. (CVE-2011-1752)

  An information disclosure flaw was found in the way the mod_dav_svn
  module processed certain URLs when path-based access control for files and
  directories was enabled. A malicious, remote user could possibly use this
  flaw to access certain files in a repository that would otherwise not be
  accessible to them. Note: This vulnerability cannot be triggered if the
  SVNPathAuthz directive is set to 'short_circuit'. (CVE-2011-1921)

  Red Hat would like to thank the Apache Subversion project for reporting
  these issues. Upstream acknowledges Joe Schaefer of the Apache Software
  Foundation as the original reporter of CVE-2011-1752, Ivan Zhakov of
  VisualSVN as the original reporter of CVE-2011-1783, and Kamesh
  Jayachandran of CollabNet, Inc. as the original reporter of CVE-2011-1921.

  All Subversion users should upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing the
  updated packages, you must restart the httpd daemon, if you are using
  mod_dav_svn, for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.6.11~7.el5_6.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.6.11~7.el5_6.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.6.11~7.el5_6.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.6.11~7.el5_6.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.6.11~7.el5_6.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.6.11~7.el5_6.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
