# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.880691");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_xref(name:"CESA", value:"2009:1580");
  script_cve_id("CVE-2009-1891", "CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_name("CentOS Update for httpd CESA-2009:1580 centos4 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-November/016318.html");
  script_xref(name:"URL", value:"http://kbase.redhat.com/faq/docs/DOC-20491");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"httpd on CentOS 4");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular Web server.

  A flaw was found in the way the TLS/SSL (Transport Layer Security/Secure
  Sockets Layer) protocols handle session renegotiation. A man-in-the-middle
  attacker could use this flaw to prefix arbitrary plain text to a client's
  session (for example, an HTTPS connection to a website). This could force
  the server to process an attacker's request as if authenticated using the
  victim's credentials. This update partially mitigates this flaw for SSL
  sessions to HTTP servers using mod_ssl by rejecting client-requested
  renegotiation. (CVE-2009-3555)

  Note: This update does not fully resolve the issue for HTTPS servers. An
  attack is still possible in configurations that require a server-initiated
  renegotiation. Refer to the linked following Knowledgebase article for further
  information.

  A denial of service flaw was found in the Apache mod_deflate module. This
  module continued to compress large files until compression was complete,
  even if the network connection that requested the content was closed before
  compression completed. This would cause mod_deflate to consume large
  amounts of CPU if mod_deflate was enabled for a large file. (CVE-2009-1891)

  A NULL pointer dereference flaw was found in the Apache mod_proxy_ftp
  module. A malicious FTP server to which requests are being proxied could
  use this flaw to crash an httpd child process via a malformed reply to the
  EPSV or PASV commands, resulting in a limited denial of service.
  (CVE-2009-3094)

  A second flaw was found in the Apache mod_proxy_ftp module. In a reverse
  proxy configuration, a remote attacker could use this flaw to bypass
  intended access restrictions by creating a carefully-crafted HTTP
  Authorization header, allowing the attacker to send arbitrary commands to
  the FTP server. (CVE-2009-3095)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.52~41.ent.6.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.52~41.ent.6.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.0.52~41.ent.6.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-suexec", rpm:"httpd-suexec~2.0.52~41.ent.6.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.52~41.ent.6.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
