# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-March/017266.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880476");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0310");
  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");
  script_name("CentOS Update for firefox CESA-2011:0310 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"firefox on CentOS 4");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  A flaw was found in the way Firefox sanitized HTML content in extensions.
  If an extension loaded or rendered malicious content using the
  ParanoidFragmentSink class, it could fail to safely display the content,
  causing Firefox to execute arbitrary JavaScript with the privileges of the
  user running Firefox. (CVE-2010-1585)

  A flaw was found in the way Firefox handled dialog boxes. An attacker could
  use this flaw to create a malicious web page that would present a blank
  dialog box that has non-functioning buttons. If a user closes the dialog
  box window, it could unexpectedly grant the malicious web page elevated
  privileges. (CVE-2011-0051)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-0053, CVE-2011-0055, CVE-2011-0058, CVE-2011-0062)

  Several flaws were found in the way Firefox handled malformed JavaScript. A
  website containing malicious JavaScript could cause Firefox to execute that
  JavaScript with the privileges of the user running Firefox. (CVE-2011-0054,
  CVE-2011-0056, CVE-2011-0057)

  A flaw was found in the way Firefox handled malformed JPEG images. A
  website containing a malicious JPEG image could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-0061)

  A flaw was found in the way Firefox handled plug-ins that perform HTTP
  requests. If a plug-in performed an HTTP request, and the server sent a 307
  redirect response, the plug-in was not notified, and the HTTP request was
  forwarded. The forwarded request could contain custom headers, which could
  result in a Cross Site Request Forgery attack. (CVE-2011-0059)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.14. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  This update also fixes the following bug:

  * On Red Hat Enterprise Linux 4 and 5, running the 'firefox

  - -setDefaultBrowser' command caused warnings such as the following:

  libgnomevfs-WARNING **: Deprecated function.  User modifications to the
  MIME database are no longer supported.

  This update disables the 'setDefaultBrowser' option. Red Hat Enterprise
  Linux 4 users wishing to set a default web browser can ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.14~4.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
