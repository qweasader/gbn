# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871079");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-11-21 10:44:11 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2012-0786", "CVE-2012-0787");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for augeas RHSA-2013:1537-02");


  script_tag(name:"affected", value:"augeas on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Augeas is a utility for editing configuration. Augeas parses configuration
files in their native formats and transforms them into a tree.
Configuration changes are made by manipulating this tree and saving it back
into native configuration files. Augeas also uses 'lenses' as basic
building blocks for establishing the mapping from files into the Augeas
tree and back.

Multiple flaws were found in the way Augeas handled configuration files
when updating them. An application using Augeas to update configuration
files in a directory that is writable to by a different user (for example,
an application running as root that is updating files in a directory owned
by a non-root service user) could have been tricked into overwriting
arbitrary files or leaking information via a symbolic link or mount point
attack. (CVE-2012-0786, CVE-2012-0787)

The augeas package has been upgraded to upstream version 1.0.0, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#817753)

This update also fixes the following bugs:

  * Previously, when single quotes were used in an XML attribute, Augeas was
unable to parse the file with the XML lens. An upstream patch has been
provided ensuring that single quotes are handled as valid characters and
parsing no longer fails. (BZ#799885)

  * Prior to this update, Augeas was unable to set up the 'require_ssl_reuse'
option in the vsftpd.conf file. The updated patch fixes the vsftpd lens to
properly recognize this option, thus fixing this bug. (BZ#855022)

  * Previously, the XML lens did not support non-Unix line endings.
Consequently, Augeas was unable to load any files containing such line
endings. The XML lens has been fixed to handle files with CRLF line
endings, thus fixing this bug. (BZ#799879)

  * Previously, Augeas was unable to parse modprobe.conf files with spaces
around '=' characters in option directives. The modprobe lens has been
updated and parsing no longer fails. (BZ#826752)

All Augeas users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:1537-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00017.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'augeas'
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

  if ((res = isrpmvuln(pkg:"augeas-debuginfo", rpm:"augeas-debuginfo~1.0.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"augeas-libs", rpm:"augeas-libs~1.0.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
