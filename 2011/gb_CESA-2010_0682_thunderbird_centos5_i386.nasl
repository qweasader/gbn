# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-September/016993.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880566");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0682");
  script_cve_id("CVE-2010-2760", "CVE-2010-2765", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_name("CentOS Update for thunderbird CESA-2010:0682 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2010-3169)

  A buffer overflow flaw was found in Thunderbird. An HTML mail message
  containing malicious content could cause Thunderbird to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Thunderbird. (CVE-2010-2765)

  A use-after-free flaw and several dangling pointer flaws were found in
  Thunderbird. An HTML mail message containing malicious content could cause
  Thunderbird to crash or, potentially, execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2010-2760, CVE-2010-2767,
  CVE-2010-3167, CVE-2010-3168)

  A cross-site scripting (XSS) flaw was found in Thunderbird. Remote HTML
  content could cause Thunderbird to execute JavaScript code with the
  permissions of different remote HTML content. (CVE-2010-2768)

  Note: JavaScript support is disabled by default in Thunderbird. None of the
  above issues are exploitable unless JavaScript is enabled.

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~2.0.0.24~8.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
