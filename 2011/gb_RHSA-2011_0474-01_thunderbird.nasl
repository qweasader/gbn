# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-April/msg00028.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870426");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-05 07:14:22 +0200 (Thu, 05 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:0474-01");
  script_cve_id("CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080");
  script_name("RedHat Update for thunderbird RHSA-2011:0474-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML content. An
  HTML mail message containing malicious content could possibly lead to
  arbitrary code execution with the privileges of the user running
  Thunderbird. (CVE-2011-0080)

  An arbitrary memory write flaw was found in the way Thunderbird handled
  out-of-memory conditions. If all memory was consumed when a user viewed a
  malicious HTML mail message, it could possibly lead to arbitrary code
  execution with the privileges of the user running Thunderbird.
  (CVE-2011-0078)

  An integer overflow flaw was found in the way Thunderbird handled the HTML
  frameset tag. An HTML mail message with a frameset tag containing large
  values for the 'rows' and 'cols' attributes could trigger this flaw,
  possibly leading to arbitrary code execution with the privileges of the
  user running Thunderbird. (CVE-2011-0077)

  A flaw was found in the way Thunderbird handled the HTML iframe tag. An
  HTML mail message with an iframe tag containing a specially-crafted source
  address could trigger this flaw, possibly leading to arbitrary code
  execution with the privileges of the user running Thunderbird.
  (CVE-2011-0075)

  A flaw was found in the way Thunderbird displayed multiple marquee
  elements. A malformed HTML mail message could cause Thunderbird to execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2011-0074)

  A flaw was found in the way Thunderbird handled the nsTreeSelection
  element. Malformed content could cause Thunderbird to execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2011-0073)

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~38.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~1.5.0.12~38.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
